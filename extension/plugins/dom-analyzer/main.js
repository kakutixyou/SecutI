// DOM解析プラグイン：ページ内の危険要素を探す
export default class DomAnalyzerPlugin {
    constructor({ eventDispatcher, apiClient }) {
        this.eventDispatcher = eventDispatcher;
        this.apiClient = apiClient;
    }

    async analyze(context) {
        // plugins/dom-analyzer/main.js の一部
    const reasons = [];
    let score = 0;

    // 1. 「爆音」や「ループ」の予兆をチェック
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
        if (script.innerText.includes('while(true)') || script.innerText.includes('alert(')) {
            score += 40;
            reasons.append('ブラウザをロックさせる可能性のあるコードを検出');
        }
    });

    // 2. ボタンや画像に仕込まれた「怪しいクリックイベント」
    const suspiciousElements = document.querySelectorAll('[onclick]');
    suspiciousElements.forEach(el => {
        const code = el.getAttribute('onclick');
        if (code.includes('location.href') && !code.includes(window.location.hostname)) {
            score += 30;
            reasons.append(`ボタンに外部サイトへの強制移動が仕込まれています: ${el.tagName}`);
        }
    });

    return {
        pluginId: 'dom-analyzer',
        score: score,
        severity: score > 50 ? 'high' : 'medium',
        reasons: reasons
    };

        // 例：パスワード入力欄があるかチェック
        const passwordFields = document.querySelectorAll('input[type="password"]');
        
        // 例：隠しリンクがあるかチェック (簡易版)
        const hiddenLinks = Array.from(document.querySelectorAll('a')).filter(a => {
            return a.style.display === 'none' || a.style.opacity === '0';
        });

        if (passwordFields.length > 0) {
            return {
                pluginId: 'dom-analyzer',
                score: 30, // 危険度スコア加算
                severity: 'medium',
                reasons: [
                    'パスワード入力欄が検出されました（フィッシングの可能性）',
                    `隠しリンクが ${hiddenLinks.length} 件検出されました`
                ]
            };
        }
        return null; // 異常なし
    }
    
}