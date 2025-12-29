// プラグインマネージャー：全ての指揮者
class PluginManager {
    constructor({ eventDispatcher, apiClient }) {
        this.eventDispatcher = eventDispatcher;
        this.apiClient = apiClient;
        this.plugins = new Map();
    }

    // プラグイン設定(plugins.json)を読み込み、JSファイルを動的にロードする
    async init() {
        try {
            const configUrl = chrome.runtime.getURL('plugins/plugins.json');
            const response = await fetch(configUrl);
            const config = await response.json();

            for (const pluginInfo of config.plugins) {
                if (!pluginInfo.enabled) continue;

                // ES Modulesとして動的インポート
                const scriptUrl = chrome.runtime.getURL(`plugins/${pluginInfo.id}/main.js`);
                const module = await import(scriptUrl);
                
                // プラグインクラスをインスタンス化
                const instance = new module.default({
                    eventDispatcher: this.eventDispatcher,
                    apiClient: this.apiClient
                });

                this.plugins.set(pluginInfo.id, { info: pluginInfo, instance });
            }
            console.log(`[secutI] Loaded ${this.plugins.size} plugins.`);
        } catch (e) {
            console.error('[secutI] Plugin loading failed:', e);
        }
    }

    // 全プラグインを実行
    async executeAll(context) {
        let allResults = [];
        for (const [id, plugin] of this.plugins) {
            try {
                // 各プラグインの analyze メソッドを呼ぶ
                const result = await plugin.instance.analyze(context);
                if (result) {
                    allResults.push(result);
                }
            } catch (e) {
                console.error(`[secutI] Plugin execution error (${id}):`, e);
            }
        }
        return allResults;
    }
}
window.PluginManager = PluginManager;