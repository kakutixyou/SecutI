// -------------------------------------------------------
// ⚙️ config.js
// アプリケーション全体の設定値と定数を管理
// -------------------------------------------------------

// 定数定義
 const CONSTANTS = {
  // キャッシュバスターやID生成用
  RANDOM_ID: 'shield-' + Math.random().toString(36).substring(2, 9),
  // バックエンドAPIのURL（ローカル開発用）
  BACKEND_URL: 'http://127.0.0.1:5000',
  // 警告を出すスコアの閾値
  MIN_SCORE_TO_WARN: 35
};

// デフォルト設定
const DEFAULT_CONFIG = {
  enabledPlugins: ['whois-checker', 'url-pattern', 'dom-analyzer', 'form-analyzer', 'redirect-detector', 'script-analyzer'],
  minScoreToWarn: CONSTANTS.MIN_SCORE_TO_WARN,
  showDetailedWarnings: true,
  autoBlock: false,
  whitelist: [],     // 信頼するドメインのリスト
  detectionLog: []   // 過去の検知ログ
};

// 現在の設定（メモリ上）
 let CONFIG = { ...DEFAULT_CONFIG };

/**
 * Chromeストレージから設定を読み込む
 */
 async function loadConfig() {
  try {
    const result = await chrome.storage.local.get('secutiConfig');
    if (result.secutiConfig) {
      // デフォルト設定に、保存された設定を上書きマージ
      CONFIG = { ...DEFAULT_CONFIG, ...result.secutiConfig };
    }
    console.log('✅ secutI: 設定読み込み完了');
  } catch (error) {
    console.warn('⚠️ secutI: 設定読み込み失敗、デフォルトを使用', error);
  }
}

/**
 * 現在の設定をChromeストレージに保存する
 */
 async function saveConfig() {
  try {
    await chrome.storage.local.set({ secutiConfig: CONFIG });
  } catch (error) {
    console.error('❌ secutI: 設定保存エラー', error);
  }
}