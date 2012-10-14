#include "ntlmauthplugin.h"

#include "definitions.h"
#include <definitions/namespaces.h>
#include <definitions/optionnodes.h>
#include <definitions/optionvalues.h>
#include <definitions/xmppfeatureorders.h>
#include <definitions/xmppfeaturepluginorders.h>
#include "ntlmauth.h"

NtlmAuthPlugin::NtlmAuthPlugin()
{
	FXmppStreams = NULL;
	FOptionsManager = NULL;
	FAccountManager = NULL;
}

NtlmAuthPlugin::~NtlmAuthPlugin()
{

}

void NtlmAuthPlugin::pluginInfo(IPluginInfo *APluginInfo)
{
	APluginInfo->name = tr("NTLM Authentication");
	APluginInfo->description = tr("Allows to log in to Jabber server using NTLM authentication");
	APluginInfo->version = "1.1";
	APluginInfo->author = "Potapov S.A. aka Lion";
	APluginInfo->homePage = "http://code.google.com/p/vacuum-plugins";
	APluginInfo->dependences.append(XMPPSTREAMS_UUID);
}

bool NtlmAuthPlugin::initConnections(IPluginManager *APluginManager, int &AInitOrder)
{
	Q_UNUSED(AInitOrder);

	IPlugin *plugin = APluginManager->pluginInterface("IXmppStreams").value(0,NULL);
	if (plugin)
		FXmppStreams = qobject_cast<IXmppStreams *>(plugin->instance());

	plugin = APluginManager->pluginInterface("IOptionsManager").value(0,NULL);
	if (plugin)
		FOptionsManager = qobject_cast<IOptionsManager *>(plugin->instance());

	plugin = APluginManager->pluginInterface("IAccountManager").value(0,NULL);
	if (plugin)
		FAccountManager = qobject_cast<IAccountManager *>(plugin->instance());

	return FXmppStreams!=NULL;
}

bool NtlmAuthPlugin::initObjects()
{
	if (FXmppStreams)
	{
		FXmppStreams->registerXmppFeature(XFO_SASL,NS_FEATURE_SASL);
		FXmppStreams->registerXmppFeaturePlugin(XFPO_NTLMAUTH,NS_FEATURE_SASL,this);
	}
	if (FOptionsManager)
	{
		FOptionsManager->insertOptionsHolder(this);
	}
	return true;
}

bool NtlmAuthPlugin::initSettings()
{
	Options::setDefaultValue(OPV_ACCOUNT_ENABLENTLMAUTH,true);
	return true;
}

QMultiMap<int, IOptionsWidget *> NtlmAuthPlugin::optionsWidgets(const QString &ANodeId, QWidget *AParent)
{
	QMultiMap<int, IOptionsWidget *> widgets;
	if (FOptionsManager)
	{
		QStringList nodeTree = ANodeId.split(".",QString::SkipEmptyParts);
		if (nodeTree.count()==2 && nodeTree.at(0)==OPN_ACCOUNTS)
		{
			OptionsNode aoptions = Options::node(OPV_ACCOUNT_ITEM,nodeTree.at(1));
			widgets.insertMulti(OWO_ACCOUNT_NTLMAUTH, FOptionsManager->optionsNodeWidget(aoptions.node("enable-ntlm-auth"),tr("Allow NTLM authentication on server"),AParent));
		}
	}
	return widgets;
}

QList<QString> NtlmAuthPlugin::xmppFeatures() const
{
	return QList<QString>() << NS_FEATURE_SASL;
}

IXmppFeature *NtlmAuthPlugin::newXmppFeature(const QString &AFeatureNS, IXmppStream *AXmppStream)
{
	if (AFeatureNS == NS_FEATURE_SASL)
	{
		IAccount *account = FAccountManager!=NULL ? FAccountManager->accountByStream(AXmppStream->streamJid()) : NULL;
		if (account==NULL || account->optionsNode().value("enable-ntlm-auth").toBool())
		{
			IXmppFeature *feature = new NtlmAuth(AXmppStream);
			connect(feature->instance(),SIGNAL(featureDestroyed()),SLOT(onFeatureDestroyed()));
			emit featureCreated(feature);
			return feature;
		}
	}
	return NULL;
}

void NtlmAuthPlugin::onFeatureDestroyed()
{
	IXmppFeature *feature = qobject_cast<IXmppFeature *>(sender());
	if (feature)
		emit featureDestroyed(feature);
}

Q_EXPORT_PLUGIN2(plg_ntlmauth, NtlmAuthPlugin)
