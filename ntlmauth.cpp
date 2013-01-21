#include "ntlmauth.h"

#include <QDomElement>
#include <definitions/namespaces.h>
#include <definitions/internalerrors.h>
#include <definitions/xmppstanzahandlerorders.h>
#include <interfaces/iconnectionmanager.h>
#include <utils/xmpperror.h>
#include "definitions.h"

static PSecurityFunctionTable SecFuncTable = InitSecurityInterface();

NtlmAuth::NtlmAuth(IXmppStream *AXmppStream) : QObject(AXmppStream->instance())
{
	FXmppStream = AXmppStream;
}

NtlmAuth::~NtlmAuth()
{
	FXmppStream->removeXmppStanzaHandler(XSHO_XMPP_FEATURE,this);
	emit featureDestroyed();
}

bool NtlmAuth::xmppStanzaIn(IXmppStream *AXmppStream, Stanza &AStanza, int AOrder)
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
			}
			else
			{
				emit error(XmppError(IERR_NTLMAUTH_FAILED));
			}

			LocalFree(ob.pvBuffer);
		}
		else
		{
			FXmppStream->removeXmppStanzaHandler(XSHO_XMPP_FEATURE,this);
			if (AStanza.tagName() == "success")
			{
				deleteLater();
				emit finished(true);
			}
			else if (AStanza.tagName() == "failure")
			{
				emit error(XmppStanzaError(AStanza.element()));
			}
			else if (AStanza.tagName() == "abort")
			{
				emit error(XmppError(IERR_NTLMAUTH_ABORTED));
			}
			else
			{
				emit error(XmppError(IERR_NTLMAUTH_INVALID_RESPONCE));
			}
		}
		return true;
	}
	return false;
}

bool NtlmAuth::xmppStanzaOut(IXmppStream *AXmppStream, Stanza &AStanza, int AOrder)
{
	Q_UNUSED(AXmppStream);
	Q_UNUSED(AStanza);
	Q_UNUSED(AOrder);
	return false;
}

QString NtlmAuth::featureNS() const
{
	return NS_FEATURE_SASL;
}

IXmppStream *NtlmAuth::xmppStream() const
{
	return FXmppStream;
}

bool NtlmAuth::start(const QDomElement &AElem)
{
	if (SecFuncTable && AElem.tagName()=="mechanisms")
	{
		if (!xmppStream()->isEncryptionRequired() || xmppStream()->connection()->isEncrypted())
		{
			QDomElement mechElem = AElem.firstChildElement("mechanism");
			if (mechElem.text() == "NTLM")
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
					return true;
				}
				else
				{
					emit error(XmppError(IERR_NTLMAUTH_NOT_STARTED));
				}
			}
		}
		else
		{
			emit error(XmppError(IERR_XMPPSTREAM_NOT_SECURE));
		}
	}
	deleteLater();
	return false;
}
