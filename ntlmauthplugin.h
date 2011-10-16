#ifndef NTLMAUTHPLUGIN_H
#define NTLMAUTHPLUGIN_H

#include <interfaces/ipluginmanager.h>
#include <interfaces/ixmppstreams.h>

#define NTLMAUTH_UUID "{AF2565C7-B689-4776-A40A-187C969CDED3}"

class NtlmAuthPlugin : 
	public QObject,
	public IPlugin,
	public IXmppFeaturesPlugin
{
	Q_OBJECT;
	Q_INTERFACES(IPlugin IXmppFeaturesPlugin);
public:
	NtlmAuthPlugin();
	~NtlmAuthPlugin();
	//IPlugin
	virtual QObject *instance() { return this; }
	virtual QUuid pluginUuid() const { return NTLMAUTH_UUID; }
	virtual void pluginInfo(IPluginInfo *APluginInfo);
	virtual bool initConnections(IPluginManager *APluginManager, int &AInitOrder);
	virtual bool initObjects();
	virtual bool initSettings() { return true; }
	virtual bool startPlugin() { return true; }
	//IXmppFeaturesPlugin
	virtual QList<QString> xmppFeatures() const;
	virtual IXmppFeature *newXmppFeature(const QString &AFeatureNS, IXmppStream *AXmppStream);
signals:
	void featureCreated(IXmppFeature *AFeature);
	void featureDestroyed(IXmppFeature *AFeature);
protected slots:
	void onFeatureDestroyed();
private:
	IXmppStreams *FXmppStreams;
};

#endif // NTLMAUTHPLUGIN_H
