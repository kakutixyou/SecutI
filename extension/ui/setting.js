// -------------------------------------------------------
// 🛡️ secutI - 設定画面スクリプト
// -------------------------------------------------------

// プラグイン定義
const PLUGINS = [
  {
    id: 'whois-checker',
    name: 'ドメイン年齢チェック',
    description: 'WHOIS情報を取得してドメインの作成日を確認',
    requiresBackend: true
  },
  {
    id: 'url-pattern',
    name: 'URL構造解析',
    description: 'URLのパターンからフィッシングサイトを検出',
    requiresBackend: true
  },
  {
    id: 'dom-analyzer',
    name: 'ページ要素解析',
    description: 'フォームやパスワード入力欄を検出',
    requiresBackend: false
  }
];

// デフォルト設定
const DEFAULT_CONFIG = {
  enabledPlugins: ['whois-checker', 'url-pattern', 'dom-analyzer'],
  minScoreToWarn: 30,
  showDetailedWarnings: true,
  autoBlock: false,
  whitelist: [],
  detectionLog: []
};

// 現在の設定
let currentConfig = { ...DEFAULT_CONFIG };

// -------------------------------------------------------
// 初期化
// -------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  renderPlugins();
  renderWhitelist();
  renderLog();
  attachEventListeners();
});

// -------------------------------------------------------
// 設定の読み込み
// -------------------------------------------------------
async function loadSettings() {
  try {
    const result = await chrome.storage.local.get('secutiConfig');
    if (result.secutiConfig) {
      currentConfig = { ...DEFAULT_CONFIG, ...result.secutiConfig };
    }
    
    // UIに反映
    document.getElementById('minScoreSlider').value = currentConfig.minScoreToWarn;
    document.getElementById('scoreValue').textContent = currentConfig.minScoreToWarn;
    
    console.log('✅ 設定を読み込みました', currentConfig);
  } catch (error) {
    console.error('❌ 設定の読み込みエラー', error);
  }
}

// -------------------------------------------------------
// 設定の保存
// -------------------------------------------------------
async function saveSettings() {
  try {
    await chrome.storage.local.set({ secutiConfig: currentConfig });
    showNotification('設定を保存しました');
    console.log('✅ 設定を保存しました', currentConfig);
  } catch (error) {
    console.error('❌ 設定の保存エラー', error);
    showNotification('保存に失敗しました', true);
  }
}

// -------------------------------------------------------
// プラグイン一覧の描画
// -------------------------------------------------------
function renderPlugins() {
  const container = document.getElementById('pluginList');
  container.innerHTML = '';

  PLUGINS.forEach(plugin => {
    const isEnabled = currentConfig.enabledPlugins.includes(plugin.id);
    
    const item = document.createElement('div');
    item.className = 'plugin-item';
    item.innerHTML = `
      <div class="plugin-info">
        <div class="plugin-name">${plugin.name}</div>
        <div class="plugin-description">
          ${plugin.description}
          ${plugin.requiresBackend ? '<span style="color: #667eea;">🌐 バックエンド必要</span>' : ''}
        </div>
      </div>
      <label class="toggle">
        <input type="checkbox" ${isEnabled ? 'checked' : ''} data-plugin-id="${plugin.id}">
        <span class="slider"></span>
      </label>
    `;

    // トグル変更イベント
    const checkbox = item.querySelector('input[type="checkbox"]');
    checkbox.addEventListener('change', (e) => {
      const pluginId = e.target.dataset.pluginId;
      if (e.target.checked) {
        if (!currentConfig.enabledPlugins.includes(pluginId)) {
          currentConfig.enabledPlugins.push(pluginId);
        }
      } else {
        currentConfig.enabledPlugins = currentConfig.enabledPlugins.filter(id => id !== pluginId);
      }
      console.log('プラグイン切り替え:', pluginId, e.target.checked);
    });

    container.appendChild(item);
  });
}

// -------------------------------------------------------
// ホワイトリストの描画
// -------------------------------------------------------
function renderWhitelist() {
  const container = document.getElementById('whitelistList');
  
  if (currentConfig.whitelist.length === 0) {
    container.innerHTML = '<div class="empty-state">ホワイトリストが空です</div>';
    return;
  }

  container.innerHTML = '';
  currentConfig.whitelist.forEach(domain => {
    const item = document.createElement('div');
    item.className = 'whitelist-item';
    item.innerHTML = `
      <span class="whitelist-domain">${domain}</span>
      <button class="btn btn-danger btn-small" data-domain="${domain}">削除</button>
    `;

    // 削除ボタン
    item.querySelector('button').addEventListener('click', (e) => {
      const domain = e.target.dataset.domain;
      currentConfig.whitelist = currentConfig.whitelist.filter(d => d !== domain);
      renderWhitelist();
    });

    container.appendChild(item);
  });
}

// -------------------------------------------------------
// ログの描画
// -------------------------------------------------------
function renderLog() {
  const container = document.getElementById('logList');
  
  if (currentConfig.detectionLog.length === 0) {
    container.innerHTML = '<div class="empty-state">まだ検出履歴がありません</div>';
    return;
  }

  container.innerHTML = '';
  
  // 新しい順に並べ替え
  const sortedLog = [...currentConfig.detectionLog].reverse().slice(0, 20); // 最新20件

  sortedLog.forEach(log => {
    const item = document.createElement('div');
    item.className = 'log-item';
    
    const severityClass = log.score >= 60 ? 'high' : log.score >= 30 ? 'medium' : 'low';
    const time = new Date(log.timestamp).toLocaleString('ja-JP');

    item.innerHTML = `
      <div class="log-header">
        <div class="log-url">${truncateUrl(log.url, 50)}</div>
        <div class="log-time">${time}</div>
      </div>
      <div class="log-score log-score-${severityClass}">
        スコア: ${log.score}
      </div>
      <div class="log-reasons">
        ${log.reasons.slice(0, 3).join(' / ')}
        ${log.reasons.length > 3 ? '...' : ''}
      </div>
    `;

    container.appendChild(item);
  });
}

// -------------------------------------------------------
// イベントリスナーの設定
// -------------------------------------------------------
function attachEventListeners() {
  // スコアスライダー
  const slider = document.getElementById('minScoreSlider');
  const scoreValue = document.getElementById('scoreValue');
  
  slider.addEventListener('input', (e) => {
    scoreValue.textContent = e.target.value;
    currentConfig.minScoreToWarn = parseInt(e.target.value);
  });

  // ホワイトリスト追加
  const addBtn = document.getElementById('addWhitelistBtn');
  const input = document.getElementById('whitelistInput');
  
  addBtn.addEventListener('click', () => {
    addToWhitelist();
  });

  input.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      addToWhitelist();
    }
  });

  // ログクリア
  document.getElementById('clearLogBtn').addEventListener('click', () => {
    if (confirm('検出履歴をすべて削除しますか?')) {
      currentConfig.detectionLog = [];
      renderLog();
      showNotification('履歴をクリアしました');
    }
  });

  // 保存ボタン
  document.getElementById('saveBtn').addEventListener('click', () => {
    saveSettings();
  });
}

// -------------------------------------------------------
// ホワイトリストに追加
// -------------------------------------------------------
function addToWhitelist() {
  const input = document.getElementById('whitelistInput');
  const domain = input.value.trim().toLowerCase();

  if (!domain) {
    alert('ドメインを入力してください');
    return;
  }

  // 簡易バリデーション
  if (!isValidDomain(domain)) {
    alert('有効なドメイン名を入力してください（例: example.com）');
    return;
  }

  // 重複チェック
  if (currentConfig.whitelist.includes(domain)) {
    alert('このドメインは既に登録されています');
    return;
  }

  currentConfig.whitelist.push(domain);
  input.value = '';
  renderWhitelist();
  showNotification(`${domain} をホワイトリストに追加しました`);
}

// -------------------------------------------------------
// ユーティリティ関数
// -------------------------------------------------------
function isValidDomain(domain) {
  // 簡易的なドメイン検証
  const pattern = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i;
  return pattern.test(domain);
}

function truncateUrl(url, maxLength) {
  if (url.length <= maxLength) return url;
  return url.substring(0, maxLength) + '...';
}

function showNotification(message, isError = false) {
  const notification = document.getElementById('notification');
  notification.textContent = message;
  notification.style.background = isError ? '#dc3545' : '#28a745';
  notification.classList.add('show');

  setTimeout(() => {
    notification.classList.remove('show');
  }, 3000);
}

// -------------------------------------------------------
// 外部からの設定更新を監視
// -------------------------------------------------------
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.secutiConfig) {
    console.log('設定が外部から更新されました');
    loadSettings();
    renderPlugins();
    renderWhitelist();
    renderLog();
  }
});