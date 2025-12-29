// -------------------------------------------------------
// 🚀 main.js
// SecutI アプリケーションのメインエントリーポイント
// -------------------------------------------------------

class SecutI {
  constructor() {
    this.eventBus = new EventDispatcher();
    this.apiClient = new ApiClient(CONSTANTS.BACKEND_URL);
    this.uiController = new UIController();
    this.scriptDetector = new SuspiciousScriptDetector();
    this.impersonationDetector = new ImpersonationDetector();
  }

  /**
   * 初期化とメインプロセスの開始
   */
  async init() {
    // 二重起動防止
    if (window.__SECUTI_INITIALIZED__) {
      console.warn('⚠️ secutI: 既に初期化済みです');
      return;
    }
    window.__SECUTI_INITIALIZED__ = true;

    // 設定読み込み
    if (typeof loadConfig === 'function') {
        await loadConfig();
    }
    console.log(`🛡️ secutI: 起動 (ID: ${CONSTANTS.RANDOM_ID})`);

    // ---------------------------------------------------------
    // ▼▼▼ ホワイトリスト（信頼済みサイト）のチェック修正 ▼▼▼
    // ---------------------------------------------------------
    
    // 1. ユーザーが「信頼する」ボタンで登録したリストをチェック (Chromeストレージ)
    // utils.js の checkIsWhitelisted を Promise でラップして待機できるようにする
    const isUserTrusted = await new Promise((resolve) => {
      if (typeof checkIsWhitelisted === 'function') {
        checkIsWhitelisted((isSafe) => resolve(isSafe));
      } else {
        resolve(false); // 関数がない場合の保険
      }
    });

    if (isUserTrusted) {
      console.log('✅ secutI: ユーザー信頼済みサイトのため全機能を停止します');
      return; // ここで終了！監視もスキャンもしない
    }

    // 2. 既存の設定ファイル(CONFIG)によるホワイトリストチェック
    if (this._isWhitelisted()) {
      console.log('✅ secutI: システム信頼済みサイトのためスキップ');
      return;
    }

    // 3. ブラウザ機能やlocalhostなどのスキップチェック
    if (this._shouldSkipUrl(window.location.href)) {
      return;
    }

    // ---------------------------------------------------------
    // ▲▲▲ チェック完了。ここから下は監視・解析処理 ▲▲▲
    // ---------------------------------------------------------

    // ▼▼▼ リアルタイム監視 (ホワイトリストチェックの後に移動しました) ▼▼▼
    this._setupLiveMonitoring();

    // ▼▼▼ バックグラウンドからのメッセージ受信 (ダウンロード警告など) ▼▼▼
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'DOWNLOAD_WARNING') {
        console.warn('📥 secutI: ダウンロード警告を受信', message.downloads);
        this.uiController.showDownloadAlert(message.downloads);
      }
    });

    // メイン解析実行
    await this.checkCurrentPage();

    // フォーム送信の監視を開始
    this._setupFormGuardian();
  }

  /**
   * 現在のページを総合的に解析する
   */
  async checkCurrentPage() {
    const currentUrl = window.location.href;

    // 1. API解析（バックエンド接続、なければオフラインモード）
    let result = await this.apiClient.analyze(
      currentUrl,
      typeof CONFIG !== 'undefined' ? CONFIG.enabledPlugins : []
    );

    // バックエンドがない場合の初期構造作成
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

    // 2. フォーム解析 (ブラウザ内実行 - 静的解析)
    const formWarnings = this._scanForms();
    if (formWarnings.length > 0) {
      result.analysis.warnings.push(...formWarnings);
      result.analysis.totalScore += formWarnings.length * 20;
    }

    // 3. スクリプト解析 (Detectorモジュール使用)
    if (typeof CONFIG !== 'undefined' && CONFIG.enabledPlugins.includes('script-analyzer')) {
      const scriptReport = this.scriptDetector.scan();
      if (scriptReport.totalScore > 0) {
        console.log('🕵️‍♂️ secutI: スクリプト解析完了', scriptReport);
        result.analysis.totalScore += scriptReport.totalScore;
        result.analysis.warnings.push(...scriptReport.warnings);
      }
    }

    // 4. リダイレクト検出
    const redirectWarnings = this._detectRedirects();
    if (redirectWarnings.length > 0) {
      result.analysis.warnings.push(...redirectWarnings);
      result.analysis.totalScore += redirectWarnings.length * 15;
    }

    // 5. なりすまし検知
    const impersonationResult = this.impersonationDetector.check();
    if (impersonationResult) {
      console.warn(`🛑 secutI: なりすまし検知 - ${impersonationResult.brand}`);
      result.analysis.totalScore += impersonationResult.score;
      result.analysis.warnings.push({
        icon: '🎭',
        title: 'なりすまし疑惑',
        description: impersonationResult.reason,
        severity: impersonationResult.severity
      });
    }

    // 6. 総合スコア判定とUI表示
    if (typeof CONFIG !== 'undefined' && result.analysis.totalScore >= CONFIG.minScoreToWarn) {
      this._finalizeResult(result.analysis);
      this.uiController.showWarning(result);
    } else {
      console.log(`✅ secutI: 安全判定 (スコア: ${result.analysis.totalScore})`);
    }
  }

  // --- (以下、変更なしのメソッド群) ---

  _scanForms() {
    const forms = document.querySelectorAll('form');
    const warnings = [];
    const currentHost = window.location.hostname;

    forms.forEach((form) => {
      const action = form.getAttribute('action') || '';
      try {
        if (!action || action.startsWith('javascript:')) return;
        const actionUrl = new URL(action, window.location.origin);
        
        if (actionUrl.hostname !== currentHost) {
          const trustedServices = ['paypal.com', 'stripe.com', 'google.com'];
          if (!trustedServices.some(s => actionUrl.hostname.includes(s))) {
            warnings.push({
              icon: '📤',
              title: 'クロスドメイン送信',
              description: `フォームが外部サイト (${actionUrl.hostname}) へデータを送信します`
            });
          }
        }
        
        const hasPasswordField = form.querySelector('input[type="password"]');
        if (actionUrl.protocol === 'http:' && hasPasswordField) {
          warnings.push({
            icon: '🔓',
            title: '暗号化されていない送信',
            description: 'パスワードが平文で送信されます'
          });
        }
      } catch (e) {}
    });
    return warnings;
  }

  _detectRedirects() {
    const warnings = [];
    const metaTags = document.querySelectorAll('meta[http-equiv="refresh"]');
    metaTags.forEach(meta => {
      const content = meta.getAttribute('content');
      const match = content?.match(/(\d+);?\s*url=(.+)/i);
      if (match) {
        const delay = parseInt(match[1]);
        const targetUrl = match[2].trim();
        if (delay <= 3 && targetUrl.startsWith('http') && !targetUrl.includes(window.location.hostname)) {
          warnings.push({
            icon: '🔀',
            title: '自動リダイレクト',
            description: `${delay}秒後に外部サイトへ自動転送されます`
          });
        }
      }
    });
    return warnings;
  }

  _setupFormGuardian() {
    const SUSPICIOUS_TEXT = ['login', 'verify', 'account', 'secure', 'update', 'password', '求人', '応募', '確認', '登録', '緊急'];
    const BRAND_KEYWORDS = ['amazon', 'google', 'apple', 'microsoft', 'paypal', 'rakuten', 'yahoo', 'line'];

    document.addEventListener('submit', (e) => {
      const form = e.target;
      const action = form.getAttribute('action') || '';
      const currentHost = window.location.hostname;
      const formText = form.innerText.toLowerCase();
      let isPhishy = false;
      let reason = '';

      try {
        const actionUrl = new URL(action, window.location.origin);
        
        if (actionUrl.hostname !== currentHost) {
          const isTrusted = ['paypal.com', 'stripe.com'].some(d => actionUrl.hostname.includes(d));
          if (!isTrusted) {
            isPhishy = true;
            reason = `外部サイト (${actionUrl.hostname}) への送信`;
          }
        }

        const hasSensitiveInput = form.querySelector('input[type="password"], input[name*="card"]');
        if (hasSensitiveInput) {
          const brandMatch = BRAND_KEYWORDS.find(b => formText.includes(b));
          if (brandMatch && !currentHost.includes(brandMatch)) {
            isPhishy = true;
            reason = reason || `${brandMatch} の偽装疑惑`;
          }
        }

        // 強制確認モード (前回の要望通り true に設定)
        if (true) { 
          e.preventDefault();
          e.stopImmediatePropagation();

          let messageTitle = isPhishy ? "🚨【警告】危険な可能性" : "🛡️ セキュリティ確認";
          let messageBody = isPhishy 
            ? `理由: ${reason}\n\n送信してよろしいですか？` 
            : `送信先: ${actionUrl.hostname}\n\nフォームを送信しますか？`;

          if (confirm(`${messageTitle}\n\n${messageBody}`)) {
            form.submit();
          }
        }
      } catch (err) {}
    }, true);
    
    console.log('🛡️ secutI: フォームガーディアン有効');
  }

  _finalizeResult(analysis) {
    const score = analysis.totalScore;
    analysis.severity = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 35 ? 'medium' : 'low';
    if (!analysis.recommendation?.message) {
      analysis.recommendation = { message: this._generateWarningMessage(analysis) };
    }
  }

/**
   * ▼▼▼ 新メソッド: 似ているURLを検知する ▼▼▼
   */
  _detectTyposquatting() {
    const currentDomain = window.location.hostname;
    
    // 守りたい有名サイトのリスト
    const protectedDomains = [
      'google.com', 'google.co.jp',
      'amazon.com', 'amazon.co.jp',
      'youtube.com',
      'yahoo.co.jp',
      'rakuten.co.jp',
      'microsoft.com',
      'twitter.com', 'x.com',
      'instagram.com',
      'facebook.com'
    ];

    // すでに正規サイトにいるならチェック不要
    if (protectedDomains.includes(currentDomain)) return null;

    for (const target of protectedDomains) {
      // ドメイン名の「距離」を計算
      // 例: google.com と goggle.com は距離1
      const distance = getLevenshteinDistance(currentDomain, target);
      
      // 距離が 1〜2 なら「非常に似ている」と判断（0は完全一致なので除外）
      if (distance > 0 && distance <= 2) {
        return {
          icon: '👺',
          title: '偽サイトの疑い (URL偽装)',
          description: `URLが <b>${target}</b> に酷似しています。<br>正規サイトに行こうとしていませんか？`,
          score: 100
        };
      }
    }
    return null;
  }

  /**
   * ▼▼▼ 修正: ご要望のメッセージ生成ロジック ▼▼▼
   */
  _generateWarningMessage(analysis) {
    const score = analysis.totalScore;
    
    if (score >= 200) {
      return `企業のサービスとしてGoogleなどの大手サイトは、ページの読み込みを速くするためにコードを圧縮（Minify）したり、通信効率を上げる特殊な変換を行っています。この影響で誤検知されている可能性があります。`;
    }
    if (score >= 80) {
      return `連続した16進数エスケープシーケンスなどを4回以上検出しました。通常は難読化に使われますが、正当な理由がある場合もあります。気になる場合は詳細を確認してください。`;
    }
    if (score >= 35) {
      return `連続した16進数エスケープシーケンスなどを2回以上検出しました。気になる場合は調べてください。`;
    }
    
    return `危ないサイトは感知されませんでした。安全に利用できます。`;
  }

  _isWhitelisted() {
    // CONFIGが存在する場合のみチェック
    if (typeof CONFIG === 'undefined') return false;
    const domain = window.location.hostname;
    return CONFIG.whitelist.some(w => domain === w || domain.endsWith('.' + w));
  }
// src/main.js の _scanForms メソッドを修正

  /**
   * フォームの安全性をチェック (強化版：動的生成・キーワード検知対応)
   */
  _scanForms() {
    const forms = document.querySelectorAll('form');
    const warnings = [];
    const currentHost = window.location.hostname;

    // 怪しいURLキーワード（これらが含まれる外部ドメインへの送信は危険）
    const SUSPICIOUS_URL_WORDS = [
      'login', 'signin', 'verify', 'secure', 'account', 'update', 
      'support', 'confirm', 'bank', 'wallet'
    ];

    forms.forEach((form) => {
      const action = form.getAttribute('action') || '';
      
      // actionが空、またはJSの場合はスキップ
      if (!action || action.startsWith('javascript:')) return;

      try {
        const actionUrl = new URL(action, window.location.origin);
        const actionHost = actionUrl.hostname;

        // 1. クロスドメイン送信チェック (外部サイトへの送信)
        if (actionHost !== currentHost) {
          // ホワイトリスト（PayPalなど）以外はチェック
          const trustedServices = ['paypal.com', 'stripe.com', 'google.com'];
          if (!trustedServices.some(s => actionHost.includes(s))) {
            
            let riskScore = 30; // 基本点
            let riskDesc = `フォームが外部サイト (${actionHost}) へデータを送信します。`;

            // ▼▼▼ 追加ロジック：送信先URLの文字列解析 ▼▼▼
            
            // A. 怪しいキーワードが含まれているか？
            // 例: 求人サイトなのに送信先が "login-support-confirm..."
            const suspiciousWord = SUSPICIOUS_URL_WORDS.find(word => actionHost.includes(word));
            if (suspiciousWord) {
              riskScore += 50; // 大幅加点
              riskDesc = `⚠️ 危険: 外部の「${suspiciousWord}」関連サイトへ誘導しています。\nフィッシングの可能性が極めて高いです。`;
            }

            // B. ハイフンが多すぎるドメインか？ (例: login-support-confirm.example.net)
            // フィッシングサイトは長いドメインやハイフンを多用する傾向がある
            const hyphenCount = (actionHost.match(/-/g) || []).length;
            if (hyphenCount >= 3) {
              riskScore += 20;
              riskDesc += `\n(ドメイン構造が不自然です)`;
            }

            warnings.push({
              icon: '📤',
              title: '外部へのデータ送信 (高リスク)',
              description: riskDesc,
              score: riskScore // ここで計算したスコアを個別に持たせる（後で合算）
            });
          }
        }
        
        // 2. 非SSL送信チェック
        const hasPasswordField = form.querySelector('input[type="password"]');
        if (actionUrl.protocol === 'http:' && hasPasswordField) {
          warnings.push({
            icon: '🔓',
            title: '暗号化されていない送信',
            description: 'パスワードが平文で送信されます',
            score: 50
          });
        }

      } catch (e) {
        // URLパースエラーは無視
      }
    });

    return warnings;
  }
  _shouldSkipUrl(url) {
    const skipPatterns = ['chrome://', 'chrome-extension://', 'about:', 'localhost', '127.0.0.1', 'file://'];
    return skipPatterns.some(p => url.includes(p));
  }
/**
   * ページの「孤立度」と「リンクの健全性」をチェック
   * （手練れが隠した「リンクの少なさ」を逆探知する）
   */
  _scanPageStructure() {
    const totalLinks = document.querySelectorAll('a').length;
    const internalLinks = document.querySelectorAll('a[href^="/"], a[href^="' + window.location.origin + '"]').length;
    const dummyLinks = document.querySelectorAll('a[href="#"], a[href=""], a[href="javascript:void(0)"]').length;

    const warnings = [];
    
    // 1. リンクが極端に少ない（ランディングページ風の偽装）
    // 通常のログイン画面なら、ヘッダーやフッターに最低でも5〜10個はリンクがあるはず
    if (totalLinks < 5) {
      warnings.push({
        icon: '🏝️',
        title: 'ページが孤立しています',
        description: 'サイト内を移動するリンクが極端に少なく、偽装サイトの特徴と一致します。',
        score: 40
      });
    }

    // 2. ダミーリンクの割合が高い
    // 「会社概要」などをクリックさせないように "#" にしているケース
    if (totalLinks > 0 && (dummyLinks / totalLinks) > 0.5) {
      warnings.push({
        icon: 'd',
        title: 'ハリボテの可能性があります',
        description: '機能しないリンク（ダミー）が多数検出されました。外見だけ模倣している可能性があります。',
        score: 50
      });
    }

    return warnings;
  }
  _setupLiveMonitoring() {
    console.log('👁️ DOM監視を開始します...');
    const observer = new MutationObserver((mutations) => {
      let shouldScan = false;
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType !== 1) return;
          if (node.tagName === 'FORM' || (node.querySelector && node.querySelector('form'))) {
            shouldScan = true;
          }
        });
      }
      if (shouldScan) {
        if (this.scanTimeout) clearTimeout(this.scanTimeout);
        this.scanTimeout = setTimeout(() => {
          console.log('🛡️ 再スキャンを実行します');
          this.checkCurrentPage();
        }, 500);
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }
}

// 起動処理
(async () => {
  try {
    const startApp = async () => {
      const app = new SecutI();
      await app.init();
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', startApp);
    } else {
      await startApp();
    }
  } catch (error) {
    console.error('❌ secutI: 起動エラー', error);
  }
})();