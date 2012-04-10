#ifndef NTLMAUTHPLUGIN_H
#define NTLMAUTHPLUGIN_H

#include <interfaces/ipluginmanager.h>
#include <interfaces/ixmppstreams.h>
#include <interfaces/ioptionsmanager.h>
#include <interfaces/iaccountmanager.h>
#include <utils/options.h>

#define NTLMAUTH_UUID "{AF2565C7-B689-4776-A40A-187C969CDED3}"

class NtlmAuthPlugin : 
	public QObject,
	public IPlugin,
	public IOptionsHolder,
	public IXmppFeaturesPlugin
{
	Q_OBJECT;
	Q_INTERFACES(IPlugin IOptionsHolder IXmppFeaturesPlugin);
public:
	NtlmAuthPlugin();
	~NtlmAuthPlugin();
	//IPlugin
	virtual QObject *instance() { return this; }
	virtual QUuid pluginUuid() const { return NTLMAUTH_UUID; }
	virtual void pluginInfo(IPluginInfo *APluginInfo);
	virtual bool initConnections(IPluginManager *APluginManager, int &AInitOrder);
	virtual bool initObjects();
	virtual bool initSettings();
	virtual bool startPlugin() { return true; }
	//IOptionsHolder
	virtual QMultiMap<int, IOptionsWidget *> optionsWidgets(const QString &ANodeId, QWidget *AParent);
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
	IOptionsManager *FOptionsManager;
	IAccountManager *FAccountManager;
};

#endif // NTLMAUTHPLUGIN_H
