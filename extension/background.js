// -------------------------------------------------------
// 🛡️ secutI - background.js（強化版）
// Drive-by Download 完全対策
// -------------------------------------------------------

// -------------------------------------------------------
// グローバル変数
// -------------------------------------------------------
let enableDbd = false; // 完全遮断モードのフラグ
let userMod = null;
// 危険なファイル拡張子
const DANGEROUS_EXTENSIONS = [
  '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js',
  '.jar', '.app', '.deb', '.pkg', '.dmg', '.msi', '.apk',
  '.ps1', '.hta', '.gadget', '.application', '.cpl', '.msc'
];

// 検知キーワード
const SUSPICIOUS_KEYWORDS = [
  'virus', 'trojan', 'malware', 'ransomware', 'keylogger',
  'crack', 'keygen', 'patch', 'activator', 'loader',
  'backdoor', 'exploit', 'payload', 'rootkit'
];

// 統計情報（オプション）
let stats = {
  totalBlocked: 0,
  totalAllowed: 0,
  lastBlockedFile: null,
  lastBlockedTime: null
};

// -------------------------------------------------------
// 初期化処理
// -------------------------------------------------------
async function initialize() {
  console.log('🛡️ secutI: background.js 起動');

  await loadSettings();
  setupDownloadMonitoring();
  setupTabMonitoring();      // ★★★ Mod監視 (新規追加)
  setupStorageListener();
  setupMessageListener();

  console.log(`✅ secutI: 初期化完了 (DBD対策: ${enableDbd ? '完全遮断' : 'スマート監視'})`);
}
// -------------------------------------------------------
// ★★★ Modエンジン: ページのURLを監視（修正版） ★★★
// -------------------------------------------------------
function setupTabMonitoring() {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // ページの読み込みが完了したらチェック開始
    if (changeInfo.status === 'complete' && tab.url) {
      // ⚠️ 変数(userMod)ではなく、毎回ストレージから最新データを取得する
      // これにより、Service Workerが居眠りしていても確実に動く
      chrome.storage.local.get(['userMod'], (result) => {
        const mod = result.userMod;
        if (mod && mod.rules) {
          checkModRules(tabId, tab.url, mod);
        }
      });
    }
  });
}

// URLとModのルールを照らし合わせる
// 引数に mod を追加しました
function checkModRules(tabId, url, mod) {
  if (!url) return;

  mod.rules.forEach(rule => {
    // ルール: URLに特定の文字が含まれていたら
    if (url.includes(rule.url_pattern)) {
      console.log(`⚡ Modヒット! ルール: ${rule.url_pattern}`);
      
      // アクション: 警告(alert)を出す
      if (rule.action === 'alert') {
        executeAlert(tabId, rule.message);
      }
    }
  });
}
// -------------------------------------------------------
// 設定の読み込み
// -------------------------------------------------------
async function loadSettings() {
  try {
    const result = await chrome.storage.local.get(['enableDbd']);
    enableDbd = result.enableDbd === true;
    console.log(`📋 secutI: 設定読み込み完了 - enableDbd: ${enableDbd}`);
  } catch (error) {
    console.error('❌ secutI: 設定の読み込みエラー', error);
    enableDbd = false;
  }
}
// 画面にアラートを出す処理
function executeAlert(tabId, message) {
  chrome.scripting.executeScript({
    target: { tabId: tabId },
    func: (msg) => {
      // ブラウザ上のアラートを表示
      alert(`🛡️ [SecutI Mod Warning]\n\n${msg}`);
    },
    args: [message]
  }).catch(err => console.error('スクリプト実行エラー:', err));
}
// -------------------------------------------------------
// ストレージ変更の監視（リアルタイム更新）
// -------------------------------------------------------
function setupStorageListener() {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && changes.enableDbd) {
      const newValue = changes.enableDbd.newValue;
      const oldValue = changes.enableDbd.oldValue;

      enableDbd = newValue === true;

      console.log(
        `🔄 secutI: DBD設定が変更されました`,
        `${oldValue} → ${newValue}`,
        `(モード: ${enableDbd ? '完全遮断' : 'スマート監視'})`
      );

      // 通知でモード変更を知らせる
      showNotification(
        'モード変更',
        `${enableDbd ? '🛑 完全遮断モード' : '🟡 スマート監視モード'}に切り替わりました`
      );
    }
  });
}

// -------------------------------------------------------
// メッセージリスナー（popup.jsとの通信）
// -------------------------------------------------------
function setupMessageListener() {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getDbdStatus') {
      // 現在の状態を返す
      sendResponse({ 
        enableDbd: enableDbd,
        stats: stats
      });
      return true;
    }

    if (message.action === 'dbdModeChanged') {
      // popup.jsから即座に通知を受け取る
      enableDbd = message.enabled;
      console.log(`📬 popup.jsから通知: DBD対策を${enableDbd ? '有効' : '無効'}にしました`);
      sendResponse({ success: true, currentMode: enableDbd });
      return true;
    }

    if (message.action === 'testDownloadBlock') {
      // テスト用
      console.log('🧪 テストモード: ダウンロードブロックをシミュレート');
      showNotification(
        'テスト通知',
        `現在のモード: ${enableDbd ? '完全遮断' : 'スマート監視'}\nブロック数: ${stats.totalBlocked}`
      );
      sendResponse({ success: true });
      return true;
    }

    if (message.action === 'getStats') {
      // 統計情報を返す
      sendResponse({ stats: stats });
      return true;
    }
  });
}

// -------------------------------------------------------
// ダウンロード監視のセットアップ
// -------------------------------------------------------
function setupDownloadMonitoring() {
  chrome.downloads.onCreated.addListener((downloadItem) => {
    console.log('📥 ダウンロード検出:', downloadItem);

    if (enableDbd) {
      // モードA: 完全遮断
      blockDownload(downloadItem, '完全遮断モード発動');
    } else {
      // モードB: スマート監視
      smartMonitoring(downloadItem);
    }
  });

  console.log('👀 secutI: ダウンロード監視を開始しました');
}

// -------------------------------------------------------
// モードA: 完全遮断
// -------------------------------------------------------
function blockDownload(downloadItem, reason) {
  chrome.downloads.cancel(downloadItem.id, () => {
    stats.totalBlocked++;
    stats.lastBlockedFile = getFileName(downloadItem.filename);
    stats.lastBlockedTime = new Date().toISOString();

    console.warn(`🛑 ${reason}: ダウンロードをブロックしました`);
    console.log(`   ファイル名: ${downloadItem.filename}`);
    console.log(`   URL: ${downloadItem.url}`);
    console.log(`   累計ブロック数: ${stats.totalBlocked}`);

    showNotification(
      'ダウンロードをブロックしました',
      `${reason}\nファイル: ${getFileName(downloadItem.filename)}`
    );
  });
}

// -------------------------------------------------------
// モードB: スマート監視（強化版）
// -------------------------------------------------------
function smartMonitoring(downloadItem) {
  const filename = downloadItem.filename || '';
  const url = downloadItem.url || '';
  const lowerFilename = filename.toLowerCase();

  let shouldBlock = false;
  let blockReason = '';

  // 0. ⚠️ 最優先: Data URI / Blob URL の即座ブロック
  if (url.startsWith('data:')) {
    shouldBlock = true;
    blockReason = 'データURIからのダウンロード（Drive-by Downloadの典型パターン）';
  } else if (url.startsWith('blob:')) {
    shouldBlock = true;
    blockReason = 'JavaScriptで動的生成されたファイル（Blob URL）';
  }

  // 既にブロック決定なら以降のチェックをスキップ
  if (shouldBlock) {
    blockDownload(downloadItem, `スマート監視: ${blockReason}`);
    return;
  }

  // 1. キーワードチェック
  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (lowerFilename.includes(keyword)) {
      shouldBlock = true;
      blockReason = `疑わしいキーワード「${keyword}」を検出`;
      break;
    }
  }

  // 2. 危険な拡張子チェック
  if (!shouldBlock) {
    for (const ext of DANGEROUS_EXTENSIONS) {
      if (lowerFilename.endsWith(ext)) {
        if (!isTrustedDomain(url)) {
          shouldBlock = true;
          blockReason = `危険な実行ファイル（${ext}）を検出`;
          break;
        }
      }
    }
  }

  // 3. ファイル名が不自然（ランダム文字列）
  if (!shouldBlock && /[a-f0-9]{16,}/.test(lowerFilename)) {
    const hasDangerousExt = DANGEROUS_EXTENSIONS.some(ext => lowerFilename.endsWith(ext));
    if (hasDangerousExt) {
      shouldBlock = true;
      blockReason = '不自然なファイル名（ランダム生成の可能性）';
    }
  }

  // ブロック判定
  if (shouldBlock) {
    blockDownload(downloadItem, `スマート監視: ${blockReason}`);
  } else {
    stats.totalAllowed++;
    console.log(`✅ secutI: ダウンロードを許可しました`);
    console.log(`   ファイル名: ${filename}`);
    console.log(`   累計許可数: ${stats.totalAllowed}`);
  }
}

// -------------------------------------------------------
// 信頼できるドメインかどうかを判定
// -------------------------------------------------------
function isTrustedDomain(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    const trustedDomains = [
      'github.com', 'gitlab.com', 'bitbucket.org',
      'google.com', 'microsoft.com', 'apple.com',
      'mozilla.org', 'debian.org', 'ubuntu.com',
      'sourceforge.net', 'npmjs.com', 'pypi.org',
      'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
      'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com'
    ];

    return trustedDomains.some(domain => 
      hostname === domain || hostname.endsWith('.' + domain)
    );
  } catch (error) {
    return false;
  }
}

// -------------------------------------------------------
// ファイル名を取得（パスから抽出）
// -------------------------------------------------------
function getFileName(filepath) {
  if (!filepath) return '(不明)';
  const parts = filepath.split(/[/\\]/);
  return parts[parts.length - 1];
}

// -------------------------------------------------------
// 通知の表示
// -------------------------------------------------------
function showNotification(title, message) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: `🛡️ secutI - ${title}`,
    message: message,
    priority: 2
  }, (notificationId) => {
    if (chrome.runtime.lastError) {
      console.warn('通知の表示に失敗:', chrome.runtime.lastError);
    }
    setTimeout(() => {
      chrome.notifications.clear(notificationId);
    }, 5000);
  });
}

// -------------------------------------------------------
// 拡張機能のインストール・起動時の処理
// -------------------------------------------------------
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('🎉 secutI: 初回インストール');
    
    chrome.storage.local.set({
      enableDbd: false, // デフォルトはスマート監視モード
      enablePhishing: true, // フィッシング対策もデフォルトON
      secutiConfig: {
        enabledPlugins: ['whois-checker', 'url-pattern', 'dom-analyzer', 'script-analyzer'],
        minScoreToWarn: 35,
        showDetailedWarnings: true,
        whitelist: [],
        detectionLog: []
      }
    });

    // インストール完了通知
    showNotification(
      'インストール完了',
      'secutIがあなたのブラウジングを保護します。\n拡張機能アイコンをクリックして設定を確認してください。'
    );
  } else if (details.reason === 'update') {
    console.log(`🔄 secutI: アップデート (${details.previousVersion} → 現在)`);
  }
});

// -------------------------------------------------------
// 起動処理の実行
// -------------------------------------------------------
initialize();