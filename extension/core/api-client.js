// APIクライアント：Pythonバックエンドとの通信を担当
class ApiClient {
    constructor(baseUrl = 'http://localhost:5000') {
        this.baseUrl = baseUrl;
    }

    async analyze(url, context = {}) {
        try {
            // サーバーがまだ起動していない場合のエラーハンドリング
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000); // 2秒タイムアウト

            const response = await fetch(`${this.baseUrl}/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, context }),
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            return await response.json();
        } catch (error) {
            console.warn('[secutI] Backend not reachable (Offline mode):', error);
            return null; // サーバーダウン時はnullを返す
        }
    }
}
window.ApiClient = ApiClient;