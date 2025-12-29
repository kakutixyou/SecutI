// -------------------------------------------------------
// 🕵️‍♂️ detector.js
// スクリプト解析・難読化検知・不審な通信先の特定を行うエンジン
// -------------------------------------------------------

 class SuspiciousScriptDetector {
  constructor() {
    // 信頼できる一般的なライブラリ（これらは検査から除外して誤検知を防ぐ）
    this.trustedLibraries = [
      'jquery', 'react', 'vue', 'angular', 'backbone', 'ember',
      'lodash', 'underscore', 'moment', 'dayjs', 'axios', 'superagent',
      'bootstrap', 'foundation', 'bulma', 'tailwind',
      'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
      'ajax.googleapis.com', 'code.jquery.com',
      'google-analytics', 'googletagmanager', 'facebook.net',
      'doubleclick.net', 'googlesyndication', 'adservice.google',
      'polyfill', 'stripe', 'paypal', 'recaptcha', 'gstatic.com'
    ];

    // 検知する危険パターン定義
    this.suspiciousPatterns = [
      // Critical (即時警告レベル)
      { pattern: /\beval\s*\([^)]{10,}\)/, score: 35, severity: 'critical', reason: '複雑なコードをeval()で実行' },
      { pattern: /_0x[0-9a-f]{4,}[^a-zA-Z0-9_]{1,5}_0x[0-9a-f]{4,}/i, score: 50, severity: 'critical', reason: '難読化パターン（_0x変数が複数）' },
      { pattern: /function\s*\(\s*_0x[0-9a-f]+/i, score: 45, severity: 'critical', reason: '難読化された関数定義' },
      
      // High (危険度高)
      { pattern: /new\s+Function\s*\([^)]*['"`]/, score: 30, severity: 'high', reason: '文字列から動的に関数を生成' },
      { pattern: /setTimeout\s*\(\s*['"`][^)]*\beval\b/i, score: 35, severity: 'high', reason: 'setTimeout内でevalを実行' },
      { pattern: /document\.write\s*\([^)]*<script/i, score: 30, severity: 'high', reason: 'document.writeで外部スクリプトを挿入' },
      { pattern: /window\[['"`]\\x[0-9a-f]{2}/i, score: 28, severity: 'high', reason: '16進数エスケープでwindowプロパティにアクセス' },
      
      // Medium (注意)
      { pattern: /String\.fromCharCode\s*\([^)]{30,}\)/, score: 18, severity: 'medium', reason: '長い文字列を数値から動的生成（難読化の可能性）' },
      { pattern: /\\x[0-9A-Fa-f]{2}.{5,}\\x[0-9A-Fa-f]{2}/, score: 20, severity: 'medium', reason: '連続した16進数エスケープシーケンス' },
      { pattern: /addEventListener\s*\(\s*['"]key(down|press|up)['"][^}]{50,}(password|pass|pwd)/i, score: 25, severity: 'medium', reason: 'キー入力を監視、パスワード関連の処理' },
      { pattern: /addEventListener\s*\(\s*['"]paste['"][^}]{30,}/i, score: 15, severity: 'medium', reason: 'クリップボードの貼り付けを監視' },
      { pattern: /document\.addEventListener\s*\(\s*['"]copy['"]/i, score: 12, severity: 'medium', reason: 'コピー操作を監視' },
      
      // Low (情報) & Custom Checks
      { pattern: /\batob\s*\([^)]{30,}\)/, score: 8, severity: 'low', reason: '長いBase64文字列をデコード' },
      { pattern: /XMLHttpRequest|fetch\s*\(/i, score: 0, severity: 'info', reason: '外部通信を行うコード', customCheck: 'checkFetchTargets' }
    ];
  }

  /**
   * ページ内の全スクリプトをスキャンして解析結果を返すメインメソッド
   */
  scan() {
    const scripts = document.querySelectorAll('script');
    let totalScore = 0;
    const warnings = [];
    let trustedCount = 0;
    let analyzedCount = 0;

    scripts.forEach((script, index) => {
      const src = script.getAttribute('src') || '';
      const content = script.textContent || '';

      // 信頼済みライブラリはスキップ（パフォーマンス最適化）
      if (src && this._isTrustedLibrary(src)) {
        trustedCount++;
        return;
      }

      // 中身が空、または短すぎるスクリプトは無視
      if (!content.trim() || content.length < 50) return;

      analyzedCount++;
      let scriptScore = 0;
      const scriptWarnings = [];

      // パターンマッチング実行
      this.suspiciousPatterns.forEach((check) => {
        // カスタムチェック（fetch解析など複雑なロジック）がある場合
        if (check.customCheck && typeof this[check.customCheck] === 'function') {
          const customResult = this[check.customCheck](content, script);
          if (customResult.detected) {
            scriptScore += customResult.score;
            scriptWarnings.push({
              severity: customResult.severity,
              reason: customResult.reason,
              details: customResult.details
            });
          }
          return;
        }

        // 通常の正規表現チェック
        const match = content.match(check.pattern);
        if (match) {
          scriptScore += check.score;
          scriptWarnings.push({
            severity: check.severity,
            reason: check.reason,
            snippet: this._extractSnippet(content, match)
          });
        }
      });

      // 個別スクリプトのスコアが閾値(15)を超えたら警告に追加
      if (scriptScore >= 15) {
        totalScore += scriptScore;
        warnings.push(...scriptWarnings.map(w => ({
          icon: this._severityIcon(w.severity),
          title: '不審なスクリプトパターン',
          description: w.reason,
          severity: w.severity,
          scriptIndex: index + 1,
          snippet: w.snippet || null,
          details: w.details || null
        })));
      }
    });

    // 開発者ツールへのログ出力（デバッグ用）
    if (warnings.length > 0) {
      console.group('🕵️‍♂️ secutI: スクリプト解析結果');
      console.log(`解析対象: ${analyzedCount}個 / 信頼済み: ${trustedCount}個`);
      console.log(`総合スコア: ${totalScore}`);
      warnings.forEach((w, i) => {
        console.warn(`${i + 1}. [${w.severity}] ${w.description}`);
      });
      console.groupEnd();
    }

    return { totalScore, warnings, analyzedCount, trustedCount };
  }

  /**
   * カスタムチェック: fetch/XHR の通信先を解析する
   */
  checkFetchTargets(content, script) {
    const patterns = [
      /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
      /\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`]+)['"`]/g
    ];

    const targets = [];
    let score = 0;
    const reasons = [];

    patterns.forEach(pattern => {
      const matches = [...content.matchAll(pattern)];
      matches.forEach(match => {
        const url = match[1];
        if (!url || url.startsWith('/') || url.startsWith('.')) return;

        // 生IPアドレスへの通信 (例: 192.168.1.1)
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
          score += 35;
          targets.push(url);
          reasons.push(`IPアドレスへ直接通信: ${url}`);
        } 
        // 外部ドメインへの通信 (信頼済みAPI以外)
        else if (this._isExternalUrl(url) && !this._isTrustedApi(url)) {
          score += 18;
          targets.push(url);
          reasons.push(`外部サイトへ通信: ${this._truncateUrl(url, 50)}`);
        }

        // URL内に機密情報キーワードが含まれるか
        if (/password|passwd|pwd|secret|token|apikey|auth|credit|card/i.test(url)) {
          score += 25;
          reasons.push('機密情報がURLに含まれている可能性');
        }
      });
    });

    if (score > 0) {
      return {
        detected: true,
        score: Math.min(score, 50), // 上限50点
        severity: score >= 30 ? 'high' : 'medium',
        reason: '疑わしい外部通信が検出されました',
        details: { targets, reasons }
      };
    }

    return { detected: false };
  }

  // --- ヘルパーメソッド ---

  _isTrustedLibrary(src) {
    const lowerSrc = src.toLowerCase();
    return this.trustedLibraries.some(lib => lowerSrc.includes(lib));
  }

  _isTrustedApi(url) {
    const trustedDomains = [
      'googleapis.com', 'gstatic.com', 'cloudflare.com',
      'amazonaws.com', 'azure.com', 'firebase.com',
      'stripe.com', 'paypal.com', 'twitter.com', 'facebook.com'
    ];
    return trustedDomains.some(domain => url.includes(domain));
  }

  _isExternalUrl(url) {
    try {
      const target = new URL(url, window.location.origin);
      return target.hostname !== window.location.hostname;
    } catch {
      return false;
    }
  }

  _extractSnippet(content, match) {
    const index = content.indexOf(match[0]);
    const start = Math.max(0, index - 15);
    const end = Math.min(content.length, index + match[0].length + 15);
    return '...' + content.substring(start, end).replace(/\s+/g, ' ').trim() + '...';
  }

  _truncateUrl(url, maxLen) {
    return url.length > maxLen ? url.substring(0, maxLen) + '...' : url;
  }

  _severityIcon(severity) {
    const icons = { critical: '🚨', high: '⚠️', medium: '⚠️', low: 'ℹ️', info: '💡' };
    return icons[severity] || 'ℹ️';
  }
}