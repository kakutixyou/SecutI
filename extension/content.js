// -------------------------------------------------------
// 🛡️ secutI v0.7 - Final Edition
// Shadow DOM + 精度重視検出 + 重複エラー解消
// -------------------------------------------------------

// -------------------------------------------------------
// ⚠️ 重複宣言防止：グローバルスコープのチェック
// -------------------------------------------------------
(function() {
  'use strict';

  // 既に実行済みなら終了
  if (window.__SECUTI_INITIALIZED__) {
    console.warn('⚠️ secutI: 既に初期化済みです（重複実行を防止）');
    return;
  }
  window.__SECUTI_INITIALIZED__ = true;

  // -------------------------------------------------------
  // 定数定義
  // -------------------------------------------------------
  const RANDOM_ID = 'shield-' + Math.random().toString(36).substring(2, 9);
  const BACKEND_URL = 'http://127.0.0.1:5000';

  // デフォルト設定
  const DEFAULT_CONFIG = {
    enabledPlugins: ['whois-checker', 'url-pattern', 'dom-analyzer', 'form-analyzer', 'redirect-detector', 'script-analyzer'],
    minScoreToWarn: 35,
    showDetailedWarnings: true,
    autoBlock: false,
    whitelist: [],
    detectionLog: []
  };

  let CONFIG = { ...DEFAULT_CONFIG };

  // -------------------------------------------------------
  // 設定の読み込み・保存
  // -------------------------------------------------------
  async function loadConfig() {
    try {
      const result = await chrome.storage.local.get('secutiConfig');
      if (result.secutiConfig) {
        CONFIG = { ...DEFAULT_CONFIG, ...result.secutiConfig };
      }
      console.log('✅ secutI: 設定読み込み完了');
    } catch (error) {
      console.warn('⚠️ secutI: 設定読み込み失敗、デフォルトを使用');
    }
  }

  async function saveConfig() {
    try {
      await chrome.storage.local.set({ secutiConfig: CONFIG });
    } catch (error) {
      console.error('❌ secutI: 設定保存エラー', error);
    }
  }

  // グローバルに公開（UIControllerから参照可能に）
  window.CONFIG = CONFIG;
  window.saveConfig = saveConfig;

  // -------------------------------------------------------
  // 🕵️‍♂️ SuspiciousScriptDetector（精度重視版）
  // -------------------------------------------------------
  class SuspiciousScriptDetector {
    constructor() {
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

      this.suspiciousPatterns = [
        // Critical
        { pattern: /\beval\s*\([^)]{10,}\)/, score: 35, severity: 'critical', reason: '複雑なコードをeval()で実行' },
        { pattern: /_0x[0-9a-f]{4,}[^a-zA-Z0-9_]{1,5}_0x[0-9a-f]{4,}/i, score: 50, severity: 'critical', reason: '難読化パターン（_0x変数が複数）' },
        { pattern: /function\s*\(\s*_0x[0-9a-f]+/i, score: 45, severity: 'critical', reason: '難読化された関数定義' },
        // High
        { pattern: /new\s+Function\s*\([^)]*['"`]/, score: 30, severity: 'high', reason: '文字列から動的に関数を生成' },
        { pattern: /setTimeout\s*\(\s*['"`][^)]*\beval\b/i, score: 35, severity: 'high', reason: 'setTimeout内でevalを実行' },
        { pattern: /document\.write\s*\([^)]*<script/i, score: 30, severity: 'high', reason: 'document.writeで外部スクリプトを挿入' },
        { pattern: /window\[['"`]\\x[0-9a-f]{2}/i, score: 28, severity: 'high', reason: '16進数エスケープでwindowプロパティにアクセス' },
        // Medium
        { pattern: /String\.fromCharCode\s*\([^)]{30,}\)/, score: 18, severity: 'medium', reason: '長い文字列を数値から動的生成（難読化の可能性）' },
        { pattern: /\\x[0-9A-Fa-f]{2}.{5,}\\x[0-9A-Fa-f]{2}/, score: 20, severity: 'medium', reason: '連続した16進数エスケープシーケンス' },
        { pattern: /addEventListener\s*\(\s*['"]key(down|press|up)['"][^}]{50,}(password|pass|pwd)/i, score: 25, severity: 'medium', reason: 'キー入力を監視、パスワード関連の処理' },
        { pattern: /addEventListener\s*\(\s*['"]paste['"][^}]{30,}/i, score: 15, severity: 'medium', reason: 'クリップボードの貼り付けを監視' },
        { pattern: /document\.addEventListener\s*\(\s*['"]copy['"]/i, score: 12, severity: 'medium', reason: 'コピー操作を監視' },
        // Low
        { pattern: /\batob\s*\([^)]{30,}\)/, score: 8, severity: 'low', reason: '長いBase64文字列をデコード' },
        { pattern: /XMLHttpRequest|fetch\s*\(/i, score: 0, severity: 'info', reason: '外部通信を行うコード', customCheck: 'checkFetchTargets' }
      ];
    }

    scan() {
      const scripts = document.querySelectorAll('script');
      let totalScore = 0;
      const warnings = [];
      let trustedCount = 0;
      let analyzedCount = 0;

      scripts.forEach((script, index) => {
        const src = script.getAttribute('src') || '';
        const content = script.textContent || '';

        if (src && this._isTrustedLibrary(src)) {
          trustedCount++;
          return;
        }

        if (!content.trim() || content.length < 50) return;

        analyzedCount++;
        let scriptScore = 0;
        const scriptWarnings = [];

        this.suspiciousPatterns.forEach((check) => {
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

      if (warnings.length > 0) {
        console.group('🕵️‍♂️ secutI: スクリプト解析結果');
        console.log(`解析対象: ${analyzedCount}個 / 信頼済み: ${trustedCount}個`);
        console.log(`総合スコア: ${totalScore}`);
        console.log(`検出パターン: ${warnings.length}件`);
        warnings.forEach((w, i) => {
          console.warn(`${i + 1}. [${w.severity}] ${w.description}`);
        });
        console.groupEnd();
      }

      return { totalScore, warnings, analyzedCount, trustedCount };
    }

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

          if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
            score += 35;
            targets.push(url);
            reasons.push(`IPアドレスへ直接通信: ${url}`);
          } else if (this._isExternalUrl(url) && !this._isTrustedApi(url)) {
            score += 18;
            targets.push(url);
            reasons.push(`外部サイトへ通信: ${this._truncateUrl(url, 50)}`);
          }

          if (/password|passwd|pwd|secret|token|apikey|auth|credit|card/i.test(url)) {
            score += 25;
            reasons.push('機密情報がURLに含まれている可能性');
          }
        });
      });

      if (score > 0) {
        return {
          detected: true,
          score: Math.min(score, 50),
          severity: score >= 30 ? 'high' : 'medium',
          reason: '疑わしい外部通信が検出されました',
          details: { targets, reasons }
        };
      }

      return { detected: false };
    }

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

  // -------------------------------------------------------
  // 🎯 EventDispatcher
  // -------------------------------------------------------
  class EventDispatcher {
    constructor() {
      this.listeners = new Map();
    }
    on(event, callback) {
      if (!this.listeners.has(event)) this.listeners.set(event, []);
      this.listeners.get(event).push(callback);
    }
    emit(event, data) {
      if (this.listeners.has(event)) {
        this.listeners.get(event).forEach(callback => callback(data));
      }
    }
  }

  // -------------------------------------------------------
  // 🌐 ApiClient
  // -------------------------------------------------------
  class ApiClient {
    constructor(baseUrl) {
      this.baseUrl = baseUrl;
    }

    async analyze(url, plugins = []) {
      try {
        const response = await fetch(`${this.baseUrl}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: url,
            plugins: plugins,
            context: {
              referrer: document.referrer,
              hasPasswordField: document.querySelectorAll('input[type="password"]').length > 0,
              formCount: document.querySelectorAll('form').length,
              scriptCount: document.querySelectorAll('script').length
            }
          })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
      } catch (error) {
        console.warn('⚠️ secutI: バックエンド接続失敗（オフラインモード）');
        return null;
      }
    }
  }

// -------------------------------------------------------
// 🎨 UIController（修正版：レイアウト崩れ防止）
// -------------------------------------------------------
class UIController {
  constructor() {
    this.randomId = 'def-' + Math.random().toString(36).substring(2) + Date.now().toString(36);
    this.shadowRoot = null;
    this.hostElement = null;
    this.observer = null;
  }

  showWarning(analysisData) {
    if (document.getElementById(this.randomId)) return;

    const score = analysisData.analysis?.totalScore || 0;
    if (score < (CONFIG.minScoreToWarn || 35)) {
      console.log(`✅ secutI: 安全 (スコア: ${score})`);
      return;
    }

    console.warn(`⚠️ secutI: 警告表示 (スコア: ${score})`);

    // 1. ホスト要素作成
    this.hostElement = document.createElement('div');
    this.hostElement.id = this.randomId;
    
    // 【重要修正】all: initial でサイト側のCSS干渉を遮断
    // pointer-events: none で、透明な箱がクリックを邪魔しないようにする
    this.hostElement.style.cssText = `
      all: initial;
      display: block;
      position: fixed;
      top: 0;
      left: 0;
      width: 0;
      height: 0;
      border: none;
      z-index: 2147483647;
      pointer-events: none;
    `;

    // 2. Shadow DOM作成
    this.shadowRoot = this.hostElement.attachShadow({ mode: 'closed' });

    // 3. スタイルとコンテンツを作成
    const styleElement = this._createStyles();
    const contentElement = this._createOverlayContent(analysisData);

    // 4. Shadow DOMに封入
    this.shadowRoot.appendChild(styleElement);
    this.shadowRoot.appendChild(contentElement);

    // 5. ページに挿入（bodyではなくdocumentElementに入れることでより安全にする場合もあるが、まずはbodyで）
    document.body.appendChild(this.hostElement);

    // 6. イベントリスナー設定
    this._attachEventListeners(analysisData);

    // 7. ログ保存
    this._saveToLog(analysisData);
  }

  _createStyles() {
    const style = document.createElement('style');
    style.textContent = `
      /* ホストが pointer-events: none なので、中身は auto に戻す */
      .overlay-container {
        pointer-events: auto; 
        position: fixed; 
        top: 0; 
        left: 0; 
        width: 100%; /* 100vwだとスクロールバー分ずれるので100%にする */
        height: 100%; 
        background: rgba(0, 0, 0, 0.95);
        display: flex; 
        justify-content: center; 
        align-items: center;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        backdrop-filter: blur(10px);
        animation: fadeIn 0.3s ease-out;
        z-index: 2147483647;
        box-sizing: border-box; /* ボックスサイズを定義 */
      }
      
      /* 全体的なリセット */
      * { box-sizing: border-box; }

      @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

      .card {
        background: white; padding: 35px; border-radius: 15px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.7); 
        width: 90%; /* max-widthと併用してスマホ対応 */
        max-width: 600px; 
        max-height: 85vh;
        overflow-y: auto; 
        animation: slideUp 0.4s ease-out;
        color: #333;
        text-align: left; /* 親の継承を防ぐため明示 */
        line-height: 1.6;
      }
      @keyframes slideUp {
        from { transform: translateY(50px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }

      .header { text-align: center; margin-bottom: 20px; }
      .score-display { font-size: 52px; font-weight: bold; margin: 12px 0; line-height: 1; }
      
      .severity-critical { color: #d32f2f; }
      .severity-high { color: #f44336; }
      .severity-medium { color: #ff9800; }
      .severity-low { color: #2196f3; }

      .warning-list {
        text-align: left; margin: 20px 0; max-height: 320px; overflow-y: auto;
        border: 1px solid #e0e0e0; border-radius: 8px; padding: 10px;
        background: #fff;
      }
      .warning-item {
        background: #fff3cd; padding: 12px; margin: 8px 0;
        border-left: 4px solid #ffc107; border-radius: 5px; font-size: 14px;
        color: #333;
      }

      .btn-group { display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }
      .btn {
        flex: 1; padding: 14px; border: none; border-radius: 8px;
        font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s;
        min-width: 120px;
      }
      .btn-primary { background: #2196f3; color: white; }
      .btn-primary:hover { background: #1976d2; }
      .btn-danger { background: #f44336; color: white; }
      .btn-danger:hover { background: #d32f2f; }
      .btn-success { background: #4caf50; color: white; }
      .btn-success:hover { background: #388e3c; }
      .btn-dev { background: #607d8b; color: white; font-size: 13px; padding: 10px; width: 100%; margin-top: 10px; border:none; border-radius: 4px; cursor: pointer;}
    `;
    return style;
  }
  
  // ... (残りのメソッドは変更なしでOK)
  _createOverlayContent(analysisData) { return super._createOverlayContent ? super._createOverlayContent(analysisData) : this.originalContentMethod(analysisData); } 
  // ※注意: 元のコードの _createOverlayContent 以降はそのまま使ってください
  
  // コピペ用に、元のメソッドの中身も念のためここに書いておきます
  originalContentMethod(analysisData) {
     const analysis = analysisData.analysis || {};
     const score = analysis.totalScore || 0;
     const severity = analysis.severity || 'medium';
     const warnings = analysis.warnings || [];
     const message = analysis.recommendation?.message || 'このサイトには複数のリスク要因が検出されました。';

     const severityIcon = { critical: '🚨', high: '⚠️', medium: '⚠️', low: 'ℹ️' }[severity] || '⚠️';

     const warningListHTML = warnings.map(w => `
       <div class="warning-item">
         <strong>${w.icon || '⚠️'} ${w.title || '警告'}</strong><br>
         ${w.description}
       </div>
     `).join('');

     const container = document.createElement('div');
     container.className = 'overlay-container';
     container.innerHTML = `
       <div class="card">
         <div class="header">
           <div style="font-size: 68px; margin-bottom: 12px;">${severityIcon}</div>
           <h2 style="margin: 0; font-size: 24px;">セキュリティ警告</h2>
           <div class="score-display severity-${severity}">
             ${score.toFixed(0)}
           </div>
           <div style="color: #666; font-size: 14px;">危険度スコア (0-100)</div>
         </div>

         <div style="background: #fff3cd; padding: 16px; border-radius: 8px; margin: 20px 0;">
           <p style="margin: 0; color: #856404; font-size: 14px; line-height: 1.5;">
             ${message}
           </p>
         </div>

         ${CONFIG.showDetailedWarnings && warnings.length > 0 ? `
           <div class="warning-list">
             <h3 style="font-size: 16px; margin-bottom: 12px;">⚠️ 検出された問題:</h3>
             ${warningListHTML}
           </div>
         ` : ''}

         <div class="btn-group">
           <button class="btn btn-danger" id="btn-back">🔙 前のページに戻る</button>
           <button class="btn btn-success" id="btn-whitelist">✅ 信頼する</button>
           <button class="btn btn-primary" id="btn-proceed">⚠️ リスクを承知で進む</button>
         </div>
         
         <div style="margin-top: 18px; text-align: center;">
           <button class="btn btn-dev" id="btn-devtools">🔍 詳細情報を表示 (DevTools)</button>
         </div>
         <div style="margin-top: 15px; text-align: center; font-size: 12px; color: #999;">
           powered by secutI v0.7
         </div>
       </div>
     `;
     return container;
  }
  
  _attachEventListeners(analysisData) {
      // 元のコードと同じ
      const shadow = this.shadowRoot;
      shadow.getElementById('btn-back')?.addEventListener('click', () => { window.history.back(); });
      shadow.getElementById('btn-proceed')?.addEventListener('click', () => { this.hideWarning(); });
      shadow.getElementById('btn-whitelist')?.addEventListener('click', async () => {
        const domain = window.location.hostname;
        if (!CONFIG.whitelist.includes(domain)) {
          CONFIG.whitelist.push(domain);
          await saveConfig();
          alert(`✅ ${domain} をホワイトリストに追加しました`);
        }
        this.hideWarning();
      });
      shadow.getElementById('btn-devtools')?.addEventListener('click', () => {
        console.group('🔍 secutI: 詳細解析情報');
        console.log('解析データ:', analysisData);
        console.table(analysisData.analysis?.warnings || []);
        console.groupEnd();
        alert('F12キーを押してコンソールを確認してください。');
      });
  }

  hideWarning() {
    this.hostElement?.remove();
    if (this.observer) this.observer.disconnect();
    console.log('✅ secutI: 警告を解除しました');
  }

  _saveToLog(analysisData) {
    if (!CONFIG.detectionLog) return;
    const logEntry = {
      url: window.location.href,
      score: analysisData.analysis?.totalScore || 0,
      severity: analysisData.analysis?.severity || 'medium',
      reasons: (analysisData.analysis?.warnings || []).map(w => w.description),
      timestamp: new Date().toISOString()
    };
    CONFIG.detectionLog.unshift(logEntry);
    CONFIG.detectionLog = CONFIG.detectionLog.slice(0, 50);
    saveConfig();
  }
}

  // -------------------------------------------------------
  // 🔌 PluginManager
  // -------------------------------------------------------
  class PluginManager {
    constructor(eventBus, apiClient) {
      this.eventBus = eventBus;
      this.apiClient = apiClient;
    }

    async loadPlugins() {
      console.log(`🔌 secutI: ${CONFIG.enabledPlugins.length}個のプラグインが有効`);
    }

    getEnabledPlugins() {
      return CONFIG.enabledPlugins;
    }
  }

  // -------------------------------------------------------
  // 🚀 SecutI Main Controller
  // -------------------------------------------------------
  class SecutI {
    constructor() {
      this.eventBus = new EventDispatcher();
      this.apiClient = new ApiClient(BACKEND_URL);
      this.uiController = new UIController();
      this.pluginManager = new PluginManager(this.eventBus, this.apiClient);
      this.scriptDetector = new SuspiciousScriptDetector();
    }

    async init() {
      await loadConfig();
      console.log(`🛡️ secutI v0.7: 起動 (ID: ${RANDOM_ID})`);

      if (this._isWhitelisted()) {
        console.log('✅ secutI: ホワイトリスト登録済みサイト');
        return;
      }

      await this.pluginManager.loadPlugins();
      await this.checkCurrentPage();
      this._setupFormGuardian();
    }

    async checkCurrentPage() {
      const currentUrl = window.location.href;
      if (this._shouldSkipUrl(currentUrl)) {
        console.log('🛡️ secutI: このページはスキップします');
        return;
      }

      let result = await this.apiClient.analyze(
        currentUrl,
        this.pluginManager.getEnabledPlugins()
      );

      if (!result) {
        result = {
          status: 'success',
          analysis: {
            totalScore: 0,
            severity: 'info',
            warnings: [],
            recommendation: {}
          }
        };
      }

      // フォーム解析
      const formWarnings = this._scanForms();
      if (formWarnings.length > 0) {
        result.analysis.warnings.push(...formWarnings);
        result.analysis.totalScore += formWarnings.length * 20;
      }

      // スクリプト解析
      if (CONFIG.enabledPlugins.includes('script-analyzer')) {
        const scriptReport = this.scriptDetector.scan();
        if (scriptReport.totalScore > 0) {
          console.log('🕵️‍♂️ secutI: スクリプト解析完了', scriptReport);
          result.analysis.totalScore += scriptReport.totalScore;
          result.analysis.warnings.push(...scriptReport.warnings);
        }
      }

      // リダイレクト検出
      const redirectWarnings = this._detectRedirects();
      if (redirectWarnings.length > 0) {
        result.analysis.warnings.push(...redirectWarnings);
        result.analysis.totalScore += redirectWarnings.length * 15;
      }

      // 総合判定
      if (result.analysis.totalScore >= CONFIG.minScoreToWarn) {
        const score = result.analysis.totalScore;
        result.analysis.severity = score >= 80 ? 'critical' :
                                   score >= 60 ? 'high' :
                                   score >= 35 ? 'medium' : 'low';

        if (!result.analysis.recommendation?.message) {
          result.analysis.recommendation = {
            message: this._generateWarningMessage(result.analysis)
          };
        }

        this.uiController.showWarning(result);
      } else {
        console.log(`✅ secutI: 安全判定 (スコア: ${result.analysis.totalScore})`);
      }
    }

    _scanForms() {
      const forms = document.querySelectorAll('form');
      const warnings = [];
      const currentHost = window.location.hostname;

      forms.forEach((form) => {
        const action = form.getAttribute('action') || '';
        const method = (form.getAttribute('method') || 'GET').toUpperCase();

        if (!action || action.startsWith('javascript:')) return;

        try {
          const actionUrl = new URL(action, window.location.origin);
          const actionHost = actionUrl.hostname;

          if (actionHost !== currentHost) {
            const trustedServices = ['paypal.com', 'stripe.com', 'google.com'];
            if (!trustedServices.some(s => actionHost.includes(s))) {
              warnings.push({
                icon: '📤',
                title: 'クロスドメイン送信',
                description: `フォームが外部サイト (${actionHost}) へデータを送信します`
              });
            }
          }

          const hasPasswordField = form.querySelector('input[type="password"]');
          if (actionUrl.protocol === 'http:' && hasPasswordField) {
            warnings.push({
              icon: '🔓',
              title: '暗号化されていない送信',
              description: 'パスワードがHTTP（暗号化なし）で送信されます'
            });
          }

          if (method === 'GET' && (hasPasswordField || form.querySelector('input[type="email"]'))) {
            warnings.push({
              icon: '⚠️',
              title: '不適切な送信方式',
              description: '個人情報がURLに露出する可能性があります（GETメソッド）'
            });
          }
        } catch (e) {
          // URLパースエラーは無視
        }
      });

      return warnings;
    }

    _detectRedirects() {
      const warnings = [];

      // Meta refreshタグ
      const metaTags = document.querySelectorAll('meta[http-equiv="refresh"]');
      metaTags.forEach(meta => {
        const content = meta.getAttribute('content');
        const match = content?.match(/(\d+);?\s*url=(.+)/i);
        if (match) {
          const delay = parseInt(match[1]);
          const targetUrl = match[2].trim();
          
          if (delay <= 3 && targetUrl.startsWith('http') && 
              !targetUrl.includes(window.location.hostname)) {
            warnings.push({
              icon: '🔀',
              title: '自動リダイレクト',
              description: `${delay}秒後に外部サイトへ自動転送されます: ${targetUrl.substring(0, 50)}...`
            });
          }
        }
      });

      // JavaScript リダイレクト
      const scripts = document.querySelectorAll('script');
      scripts.forEach(script => {
        const content = script.textContent || '';
        
        const redirectPatterns = [
          /window\.location\s*=\s*['"]([^'"]+)['"]/,
          /window\.location\.href\s*=\s*['"]([^'"]+)['"]/,
          /location\.replace\s*\(\s*['"]([^'"]+)['"]\)/
        ];

        redirectPatterns.forEach(pattern => {
          const match = content.match(pattern);
          if (match && match[1].startsWith('http') && 
              !match[1].includes(window.location.hostname)) {
            warnings.push({
              icon: '🔀',
              title: 'JavaScriptリダイレクト',
              description: `スクリプトによる外部サイトへの転送: ${match[1].substring(0, 50)}...`
            });
          }
        });
      });

      return warnings;
    }

    _setupFormGuardian() {
      document.addEventListener('submit', (e) => {
        const form = e.target;
        const action = form.getAttribute('action') || '';
        const currentHost = window.location.hostname;

        try {
          const actionUrl = new URL(action, window.location.origin);
          
          if (actionUrl.hostname !== currentHost) {
            e.preventDefault();
            e.stopPropagation();

            if (confirm(
              `⚠️ セキュリティ確認\n\n` +
              `入力データを外部サイトへ送信しようとしています：\n${actionUrl.hostname}\n\n` +
              `本当に送信しますか？`
            )) {
              form.submit();
            } else {
              console.log('✋ secutI: フォーム送信をブロックしました');
            }
          }
        } catch (e) {
          // URLパースエラーは無視
        }
      }, true);

      console.log('🛡️ secutI: フォームガーディアン有効');
    }

    _generateWarningMessage(analysis) {
      const score = analysis.totalScore;
      const warningCount = analysis.warnings?.length || 0;

      if (score >= 80) {
        return `このサイトは極めて危険です。${warningCount}件の重大な問題が検出されました。アクセスを中止することを強く推奨します。`;
      } else if (score >= 60) {
        return `このサイトはフィッシング詐欺やマルウェアの可能性が高いです。${warningCount}件の問題が検出されました。`;
      } else if (score >= 35) {
        return `このサイトには疑わしい要素が含まれています。${warningCount}件の問題が検出されました。個人情報の入力は避けてください。`;
      }
      return `このサイトには若干の懸念事項があります。慎重に利用してください。`;
    }

    _isWhitelisted() {
      const domain = window.location.hostname;
      return CONFIG.whitelist.some(w => 
        domain === w || domain.endsWith('.' + w)
      );
    }

    _shouldSkipUrl(url) {
      const skipPatterns = [
        'chrome://', 'chrome-extension://', 'about:',
        'localhost', '127.0.0.1', 'file://',
        'moz-extension://', 'edge://'
      ];
      return skipPatterns.some(p => url.includes(p));
    }
  }

  // -------------------------------------------------------
  // 🎬 起動処理
  // -------------------------------------------------------
  (async () => {
    try {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', async () => {
          const app = new SecutI();
          await app.init();
        });
      } else {
        const app = new SecutI();
        await app.init();
      }
    } catch (error) {
      console.error('❌ secutI: 初期化エラー', error);
    }
  })();

})(); // IIFE終了