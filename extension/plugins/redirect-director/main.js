// -------------------------------------------------------
// 🔀 Redirect Detector Plugin - リダイレクト検出
// -------------------------------------------------------

class RedirectDetectorPlugin {
  constructor({ eventBus, apiClient }) {
    this.eventBus = eventBus;
    this.apiClient = apiClient;
    this.detectedRedirects = [];
    this.monitoring = false;
  }

  /**
   * リダイレクトの検出と解析
   */
  async analyze(context) {
    const results = {
      pluginId: 'redirect-detector',
      score: 0,
      severity: 'info',
      reasons: [],
      metadata: {
        redirects: []
      }
    };

    // 1. Meta refreshタグの検出
    const metaRedirects = this._detectMetaRefresh();
    if (metaRedirects.length > 0) {
      results.metadata.redirects.push(...metaRedirects);
      results.score += 20;
      results.reasons.push(
        `Meta refreshタグによる自動リダイレクトが検出されました（${metaRedirects.length}件）`
      );
    }

    // 2. JavaScriptリダイレクトの検出
    const jsRedirects = this._detectJavaScriptRedirects();
    if (jsRedirects.length > 0) {
      results.metadata.redirects.push(...jsRedirects);
      results.score += 25;
      results.reasons.push(
        `JavaScriptによるリダイレクトが検出されました（${jsRedirects.length}件）`
      );
    }

    // 3. 外部サイトへのリダイレクト
    const externalRedirects = results.metadata.redirects.filter(r => r.isExternal);
    if (externalRedirects.length > 0) {
      results.score += 30;
      results.reasons.push(
        '外部サイトへの自動リダイレクトが設定されています'
      );
    }

    // 4. 短時間でのリダイレクト
    const fastRedirects = results.metadata.redirects.filter(r => r.delay < 3);
    if (fastRedirects.length > 0) {
      results.score += 15;
      results.reasons.push(
        'ユーザーの確認なしに即座にリダイレクトされます'
      );
    }

    // 深刻度の判定
    if (results.score >= 50) {
      results.severity = 'high';
    } else if (results.score >= 30) {
      results.severity = 'medium';
    } else if (results.score > 0) {
      results.severity = 'low';
    }

    // コンソールに出力
    if (results.metadata.redirects.length > 0) {
      this._logToConsole(results.metadata.redirects);
    }

    // リダイレクトの監視を開始
    this._startMonitoring();

    return results.score > 0 ? results : null;
  }

  /**
   * Meta refreshタグの検出
   */
  _detectMetaRefresh() {
    const metaTags = document.querySelectorAll('meta[http-equiv="refresh"]');
    const redirects = [];

    metaTags.forEach(meta => {
      const content = meta.getAttribute('content');
      if (!content) return;

      const match = content.match(/(\d+);?\s*url=(.+)/i);
      if (match) {
        const delay = parseInt(match[1]);
        const targetUrl = match[2].trim();

        redirects.push({
          type: 'meta-refresh',
          targetUrl: targetUrl,
          delay: delay,
          isExternal: this._isExternalUrl(targetUrl),
          element: 'meta[http-equiv="refresh"]'
        });
      }
    });

    return redirects;
  }

  /**
   * JavaScriptリダイレクトの検出
   */
  _detectJavaScriptRedirects() {
    const redirects = [];
    const scripts = document.querySelectorAll('script');

    // window.location系のパターン
    const redirectPatterns = [
      /window\.location\s*=\s*["']([^"']+)["']/gi,
      /window\.location\.href\s*=\s*["']([^"']+)["']/gi,
      /window\.location\.replace\(["']([^"']+)["']\)/gi,
      /location\.href\s*=\s*["']([^"']+)["']/gi,
      /document\.location\s*=\s*["']([^"']+)["']/gi
    ];

    scripts.forEach(script => {
      const scriptContent = script.textContent;

      redirectPatterns.forEach(pattern => {
        let match;
        while ((match = pattern.exec(scriptContent)) !== null) {
          const targetUrl = match[1];

          // 変数や相対パスをスキップ
          if (targetUrl.startsWith('http') || targetUrl.startsWith('//')) {
            redirects.push({
              type: 'javascript-redirect',
              targetUrl: targetUrl,
              delay: 0, // 即座
              isExternal: this._isExternalUrl(targetUrl),
              element: 'script'
            });
          }
        }
      });
    });

    // setTimeoutやsetInterval内のリダイレクト
    const timedPatterns = [
      /setTimeout\s*\(\s*function\s*\(\)\s*{\s*window\.location/gi,
      /setInterval\s*\(\s*function\s*\(\)\s*{\s*window\.location/gi
    ];

    scripts.forEach(script => {
      const scriptContent = script.textContent;

      timedPatterns.forEach(pattern => {
        if (pattern.test(scriptContent)) {
          redirects.push({
            type: 'timed-javascript-redirect',
            targetUrl: '(動的に生成)',
            delay: 'unknown',
            isExternal: false,
            element: 'script with setTimeout/setInterval'
          });
        }
      });
    });

    return redirects;
  }

  /**
   * リダイレクトの監視開始
   */
  _startMonitoring() {
    if (this.monitoring) return;

    // window.locationの変更を監視
    const originalLocation = window.location.href;
    let checkCount = 0;
    const maxChecks = 10;

    const checkInterval = setInterval(() => {
      checkCount++;

      if (window.location.href !== originalLocation) {
        console.warn('🔀 secutI: リダイレクトが実行されました');
        console.log(`  元のURL: ${originalLocation}`);
        console.log(`  新しいURL: ${window.location.href}`);
        clearInterval(checkInterval);
      }

      if (checkCount >= maxChecks) {
        clearInterval(checkInterval);
      }
    }, 500);

    this.monitoring = true;
  }

  /**
   * 外部URLかどうかを判定
   */
  _isExternalUrl(url) {
    try {
      // 相対URLの場合は現在のドメインを基準にする
      const targetUrl = new URL(url, window.location.origin);
      return targetUrl.hostname !== window.location.hostname;
    } catch {
      return false;
    }
  }

  /**
   * コンソールに出力
   */
  _logToConsole(redirects) {
    console.group('🔀 secutI: リダイレクトの検出');

    redirects.forEach((redirect, index) => {
      console.group(`リダイレクト #${index + 1}`);

      // タイプ
      let typeLabel = redirect.type;
      if (redirect.type === 'meta-refresh') typeLabel = 'Meta Refreshタグ';
      if (redirect.type === 'javascript-redirect') typeLabel = 'JavaScript';
      if (redirect.type === 'timed-javascript-redirect') typeLabel = 'JavaScript (タイマー)';

      console.log('%c種類:', 'font-weight: bold;', typeLabel);
      console.log('%c遷移先:', 'font-weight: bold; color: #667eea;');
      console.log(`  ${redirect.targetUrl}`);

      if (redirect.delay !== 'unknown') {
        console.log('%c遅延:', 'font-weight: bold;', 
          redirect.delay === 0 ? '即座' : `${redirect.delay}秒後`
        );
      }

      if (redirect.isExternal) {
        console.warn('%c⚠️ 外部サイトへのリダイレクト', 'color: red; font-weight: bold;');
      }

      console.log('%c検出場所:', 'font-weight: bold;', redirect.element);

      console.groupEnd();
    });

    console.log('%c💡 ヒント: リダイレクトが実行される前にこのページを離れることをおすすめします', 
      'color: #999; font-style: italic;');
    console.groupEnd();
  }

  /**
   * クリーンアップ
   */
  destroy() {
    this.monitoring = false;
  }
}

// エクスポート
if (typeof module !== 'undefined' && module.exports) {
  module.exports = RedirectDetectorPlugin;
}