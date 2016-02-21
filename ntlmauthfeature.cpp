#include "ntlmauthfeature.h"

#include <QDomElement>
#include <definitions/namespaces.h>
#include <definitions/internalerrors.h>
#include <definitions/xmppstanzahandlerorders.h>
#include <interfaces/iconnectionmanager.h>
#include <utils/xmpperror.h>
#include <utils/logger.h>
#include "definitions.h"

static PSecurityFunctionTable SecFuncTable = InitSecurityInterface();

NtlmAuthFeature::NtlmAuthFeature(IXmppStream *AXmppStream) : QObject(AXmppStream->instance())
{
	FXmppStream = AXmppStream;
}

NtlmAuthFeature::~NtlmAuthFeature()
{
	FXmppStream->removeXmppStanzaHandler(XSHO_XMPP_FEATURE,this);
	emit featureDestroyed();
}

bool NtlmAuthFeature::xmppStanzaIn(IXmppStream *AXmppStream, Stanza &AStanza, int AOrder)
{
	if (AXmppStream==FXmppStream && AOrder==XSHO_XMPP_FEATURE)
	{
		if (AStanza.tagName() == "challenge")
		{
			SecBuffer ob, ib;
			SecBufferDesc obd, ibd;

			obd.ulVersion = SECBUFFER_VERSION;
			obd.cBuffers = 1;
			obd.pBuffers = &ob;

			ob.BufferType = SECBUFFER_TOKEN;
			ob.cbBuffer = FSecPackInfo->cbMaxToken;
			ob.pvBuffer = LocalAlloc(0, ob.cbBuffer);

			ibd.ulVersion = SECBUFFER_VERSION;
			ibd.cBuffers = 1;
			ibd.pBuffers = &ib;

			QByteArray chalData = QByteArray::fromBase64(AStanza.element().text().toLatin1());
			ib.BufferType = SECBUFFER_TOKEN;
			ib.cbBuffer = chalData.size();
			ib.pvBuffer = !chalData.isEmpty() ? chalData.data()  : NULL;

			DWORD ctxAttr;
			DWORD ctxReq = ISC_REQ_REPLAY_DETECT|ISC_REQ_SEQUENCE_DETECT|ISC_REQ_CONFIDENTIALITY|ISC_REQ_DELEGATE;
			int rcISC = SecFuncTable->InitializeSecurityContext(&FCredHandle, !chalData.isEmpty() ? &FCtxtHandle: NULL, NULL, ctxReq, 0, SECURITY_NATIVE_DREP, !chalData.isEmpty() ? &ibd : NULL, 0, &FCtxtHandle, &obd, &ctxAttr, NULL);

			if (rcISC==SEC_I_COMPLETE_AND_CONTINUE || rcISC==SEC_I_COMPLETE_NEEDED)
			{
				if (SecFuncTable->CompleteAuthToken != NULL)
					SecFuncTable->CompleteAuthToken(&FCtxtHandle, &obd);
				rcISC = SEC_E_OK;
			}
			else if (rcISC == SEC_I_CONTINUE_NEEDED)
			{
				rcISC = SEC_E_OK;
			}

			if (rcISC == SEC_E_OK)
			{
				QByteArray respData((const char *)ob.pvBuffer,ob.cbBuffer);

				Stanza response("response");
				response.setAttribute("xmlns",NS_FEATURE_SASL);
				response.element().appendChild(response.createTextNode(respData.toBase64()));
				FXmppStream->sendStanza(response);
				LOG_STRM_DEBUG(FXmppStream->streamJid(),QString("Response sent, challenge='%1', response='%2'").arg(QString::fromUtf8(chalData)).arg(QString::fromUtf8(respData)));
			}
			else
			{
				LOG_STRM_ERROR(FXmppStream->streamJid(),QString("Failed process authorization, challenge='%1', err=%2").arg(QString::fromUtf8(chalData)).arg(rcISC));
				emit error(XmppError(IERR_NTLMAUTH_INVALID_CHALLENGE));
			}

			LocalFree(ob.pvBuffer);
		}
		else
		{
			FXmppStream->removeXmppStanzaHandler(XSHO_XMPP_FEATURE,this);
			if (AStanza.tagName() == "success")
			{
				LOG_STRM_INFO(FXmppStream->streamJid(),"Authorization successes");
				deleteLater();
				emit finished(true);
			}
			else if (AStanza.tagName() == "failure")
			{
				XmppSaslError err(AStanza.element());
				LOG_STRM_WARNING(FXmppStream->streamJid(),QString("Authorization failed: %1").arg(err.condition()));
				emit error(err);
			}
			else
			{
				XmppError err(IERR_SASL_AUTH_INVALID_RESPONSE);
				LOG_STRM_WARNING(FXmppStream->streamJid(),QString("Authorization error: Invalid response=%1").arg(AStanza.tagName()));
				emit error(err);
			}
		}
		return true;
	}
	return false;
}

bool NtlmAuthFeature::xmppStanzaOut(IXmppStream *AXmppStream, Stanza &AStanza, int AOrder)
{
	Q_UNUSED(AXmppStream); Q_UNUSED(AStanza); Q_UNUSED(AOrder);
	return false;
}

QString NtlmAuthFeature::featureNS() const
{
	return NS_FEATURE_SASL;
}

IXmppStream *NtlmAuthFeature::xmppStream() const
{
	return FXmppStream;
}

bool NtlmAuthFeature::start(const QDomElement &AElem)
{
	if (SecFuncTable && AElem.tagName()=="mechanisms")
	{
		if (!xmppStream()->isEncryptionRequired() || xmppStream()->connection()->isEncrypted())
		{
			if (hasNtlmMechanism(AElem))
			{
				int rc = 0;
				rc += SecFuncTable->QuerySecurityPackageInfo(NTLMSP_NAME,&FSecPackInfo);
				rc += SecFuncTable->AcquireCredentialsHandle(NULL,NTLMSP_NAME,SECPKG_CRED_OUTBOUND,NULL, NULL, NULL, NULL, &FCredHandle, NULL);
				
				if (rc == SEC_E_OK)
				{
					Stanza auth("auth");
					auth.setAttribute("xmlns",NS_FEATURE_SASL).setAttribute("mechanism","NTLM");
					FXmppStream->insertXmppStanzaHandler(XSHO_XMPP_FEATURE,this);
					FXmppStream->sendStanza(auth);
					LOG_STRM_INFO(FXmppStream->streamJid(),"NTLM authorization request sent");
					return true;
				}
				else
				{
					LOG_STRM_ERROR(FXmppStream->streamJid(),QString("Failed to initialize NTLM authorization, err=%1").arg(rc));
					emit error(XmppError(IERR_NTLMAUTH_NOT_INITIALIZED));
				}
			}
		}
		else
		{
			XmppError err(IERR_XMPPSTREAM_NOT_SECURE);
			LOG_STRM_WARNING(FXmppStream->streamJid(),QString("Failed to send authorization request: %1").arg(err.condition()));
			emit error(err);
		}
	}
	deleteLater();
	return false;
}

bool NtlmAuthFeature::isSupported()
{
	return SecFuncTable!=NULL;
}

bool NtlmAuthFeature::hasNtlmMechanism(const QDomElement &AMechanisms)
{
	QDomElement mechElem = AMechanisms.firstChildElement("mechanism");
	while(!mechElem.isNull())
	{
		if (mechElem.text() == "NTLM")
			return true;
		mechElem = mechElem.nextSiblingElement("mechanism");
	}
	return false;
}
