#ifndef NTLMAUTHPLUGIN_H
#define NTLMAUTHPLUGIN_H

#include <interfaces/ipluginmanager.h>
#include <interfaces/ixmppstreammanager.h>
#include <interfaces/ioptionsmanager.h>
#include <interfaces/iaccountmanager.h>
#include <utils/xmpperror.h>
#include <utils/options.h>

#define NTLMAUTH_UUID "{AF2565C7-B689-4776-A40A-187C969CDED3}"

class NtlmAuthFeatureFactory : 
	public QObject,
	public IPlugin,
	public IOptionsDialogHolder,
	public IXmppFeatureFactory
{
	Q_OBJECT;
	Q_INTERFACES(IPlugin IOptionsDialogHolder IXmppFeatureFactory);
public:
	NtlmAuthFeatureFactory();
	~NtlmAuthFeatureFactory();
	//IPlugin
	virtual QObject *instance() { return this; }
	virtual QUuid pluginUuid() const { return NTLMAUTH_UUID; }
	virtual void pluginInfo(IPluginInfo *APluginInfo);
	virtual bool initConnections(IPluginManager *APluginManager, int &AInitOrder);
	virtual bool initObjects();
	virtual bool initSettings();
	virtual bool startPlugin() { return true; }
	//IOptionsHolder
	virtual QMultiMap<int, IOptionsDialogWidget *> optionsDialogWidgets(const QString &ANodeId, QWidget *AParent);
	//IXmppFeaturesPlugin
	virtual QList<QString> xmppFeatures() const;
	virtual IXmppFeature *newXmppFeature(const QString &AFeatureNS, IXmppStream *AXmppStream);
signals:
	void featureCreated(IXmppFeature *AFeature);
	void featureDestroyed(IXmppFeature *AFeature);
protected slots:
	void onFeatureDestroyed();
private:
	IOptionsManager *FOptionsManager;
	IAccountManager *FAccountManager;
	IXmppStreamManager *FXmppStreammanager;
};

#endif // NTLMAUTHPLUGIN_H
