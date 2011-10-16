#include "ntlmauthplugin.h"

#include <definitions.h>
#include <definitions/namespaces.h>
#include <definitions/xmppfeatureorders.h>
#include <definitions/xmppfeaturepluginorders.h>
#include "ntlmauth.h"

NtlmAuthPlugin::NtlmAuthPlugin()
{
	FXmppStreams = NULL;
}

NtlmAuthPlugin::~NtlmAuthPlugin()
{

}

void NtlmAuthPlugin::pluginInfo(IPluginInfo *APluginInfo)
{
	APluginInfo->name = tr("NTLM Authentication");
	APluginInfo->description = tr("Allows to log in to Jabber server using NTLM authentication");
	APluginInfo->version = "1.0";
	APluginInfo->author = "Potapov S.A. aka Lion";
	APluginInfo->homePage = "http://code.google.com/p/vacuum-plugins";
	APluginInfo->dependences.append(XMPPSTREAMS_UUID);
}

bool NtlmAuthPlugin::initConnections(IPluginManager *APluginManager, int &AInitOrder)
{
	Q_UNUSED(AInitOrder);

	IPlugin *plugin = APluginManager->pluginInterface("IXmppStreams").value(0,NULL);
	if (plugin)
	{
		FXmppStreams = qobject_cast<IXmppStreams *>(plugin->instance());
	}
	return FXmppStreams!=NULL;
}

bool NtlmAuthPlugin::initObjects()
{
	if (FXmppStreams)
	{
		FXmppStreams->registerXmppFeature(XFO_SASL,NS_FEATURE_SASL);
		FXmppStreams->registerXmppFeaturePlugin(XFPO_NTLMAUTH,NS_FEATURE_SASL,this);
	}
	return true;
}

QList<QString> NtlmAuthPlugin::xmppFeatures() const
{
	return QList<QString>() << NS_FEATURE_SASL;
}

IXmppFeature *NtlmAuthPlugin::newXmppFeature(const QString &AFeatureNS, IXmppStream *AXmppStream)
{
	if (AFeatureNS == NS_FEATURE_SASL)
	{
		IXmppFeature *feature = new NtlmAuth(AXmppStream);
		connect(feature->instance(),SIGNAL(featureDestroyed()),SLOT(onFeatureDestroyed()));
		emit featureCreated(feature);
		return feature;
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
