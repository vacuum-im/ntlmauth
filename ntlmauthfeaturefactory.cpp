#include "ntlmauthfeaturefactory.h"

#include <definitions/namespaces.h>
#include <definitions/optionnodes.h>
#include <definitions/optionvalues.h>
#include <definitions/xmppfeatureorders.h>
#include <definitions/xmppfeaturefactoryorders.h>
#include <utils/logger.h>
#include "definitions.h"
#include "ntlmauthfeature.h"

NtlmAuthFeatureFactory::NtlmAuthFeatureFactory()
{
	FXmppStreammanager = NULL;
	FOptionsManager = NULL;
	FAccountManager = NULL;
}

NtlmAuthFeatureFactory::~NtlmAuthFeatureFactory()
{

}

void NtlmAuthFeatureFactory::pluginInfo(IPluginInfo *APluginInfo)
{
	APluginInfo->name = tr("NTLM Authentication");
	APluginInfo->description = tr("Allows to log in to Jabber server using NTLM authentication");
	APluginInfo->version = "1.2.0";
	APluginInfo->author = "Potapov S.A. aka Lion";
	APluginInfo->homePage = "https://github.com/Vacuum-IM/ntlmauth";
	APluginInfo->dependences.append(XMPPSTREAMS_UUID);
}

bool NtlmAuthFeatureFactory::initConnections(IPluginManager *APluginManager, int &AInitOrder)
{
	Q_UNUSED(AInitOrder);

	IPlugin *plugin = APluginManager->pluginInterface("IXmppStreamManager").value(0,NULL);
	if (plugin)
		FXmppStreammanager = qobject_cast<IXmppStreamManager *>(plugin->instance());

	plugin = APluginManager->pluginInterface("IOptionsManager").value(0,NULL);
	if (plugin)
		FOptionsManager = qobject_cast<IOptionsManager *>(plugin->instance());

	plugin = APluginManager->pluginInterface("IAccountManager").value(0,NULL);
	if (plugin)
		FAccountManager = qobject_cast<IAccountManager *>(plugin->instance());

	return FXmppStreammanager!=NULL;
}

bool NtlmAuthFeatureFactory::initObjects()
{
	XmppError::registerError(NS_INTERNAL_ERROR,IERR_NTLMAUTH_NOT_INITIALIZED,tr("Failed to initialize NTLM authorization"));
	XmppError::registerError(NS_INTERNAL_ERROR,IERR_NTLMAUTH_INVALID_CHALLENGE,tr("Failed to process NTLM authorization"));

	if (FXmppStreammanager)
	{
		FXmppStreammanager->registerXmppFeature(XFO_SASL,NS_FEATURE_SASL);
		FXmppStreammanager->registerXmppFeatureFactory(XFFO_NTLMAUTH,NS_FEATURE_SASL,this);
	}
	if (FOptionsManager)
	{
		FOptionsManager->insertOptionsDialogHolder(this);
	}
	return true;
}

bool NtlmAuthFeatureFactory::initSettings()
{
	Options::setDefaultValue(OPV_ACCOUNT_ENABLENTLMAUTH,true);
	return true;
}

QMultiMap<int, IOptionsDialogWidget *> NtlmAuthFeatureFactory::optionsDialogWidgets(const QString &ANodeId, QWidget *AParent)
{
	QMultiMap<int, IOptionsDialogWidget *> widgets;
	if (FOptionsManager)
	{
		QStringList nodeTree = ANodeId.split(".",QString::SkipEmptyParts);
		if (nodeTree.count()==3 && nodeTree.at(0)==OPN_ACCOUNTS && nodeTree.at(2)=="Parameters")
		{
			OptionsNode options = Options::node(OPV_ACCOUNT_ITEM,nodeTree.at(1));
			IOptionsDialogWidget *widget = FOptionsManager->newOptionsDialogWidget(options.node("enable-ntlm-auth"),tr("Use system user parameters for authorization"),AParent);
			widget->instance()->setEnabled(NtlmAuthFeature::isSupported());
			widgets.insertMulti(OWO_ACCOUNTS_PARAMS_NTLMAUTH,widget);
		}
	}
	return widgets;
}

QList<QString> NtlmAuthFeatureFactory::xmppFeatures() const
{
	return QList<QString>() << NS_FEATURE_SASL;
}

IXmppFeature *NtlmAuthFeatureFactory::newXmppFeature(const QString &AFeatureNS, IXmppStream *AXmppStream)
{
	if (AFeatureNS == NS_FEATURE_SASL)
	{
		IAccount *account = FAccountManager!=NULL ? FAccountManager->findAccountByStream(AXmppStream->streamJid()) : NULL;
		if (account==NULL || account->optionsNode().value("enable-ntlm-auth").toBool())
		{
			if (NtlmAuthFeature::isSupported())
			{
				LOG_STRM_INFO(AXmppStream->streamJid(),"NTLMAuth XMPP stream feature created");
				IXmppFeature *feature = new NtlmAuthFeature(AXmppStream);				connect(feature->instance(),SIGNAL(featureDestroyed()),SLOT(onFeatureDestroyed()));				emit featureCreated(feature);				return feature;			}
			else
			{
				LOG_STRM_WARNING(AXmppStream->streamJid(),"Failed to create NTLMAuth XMPP stream feature: Not supported");
			}
		}
	}
	return NULL;
}

void NtlmAuthFeatureFactory::onFeatureDestroyed()
{
	IXmppFeature *feature = qobject_cast<IXmppFeature *>(sender());
	if (feature)
	{
		LOG_STRM_INFO(feature->xmppStream()->streamJid(),"NTLMAuth XMPP stream feature destroyed");
		emit featureDestroyed(feature);
	}
}

Q_EXPORT_PLUGIN2(plg_ntlmauth, NtlmAuthFeatureFactory)
