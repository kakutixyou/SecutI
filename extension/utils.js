// -------------------------------------------------------
// 🛠️ utils.js
// イベント管理やAPI通信、および共通の便利機能
// -------------------------------------------------------

// src/utils.js に追加

/**
 * 🧩 プラグインマネージャー
 * JSONルールを安全に解析・適用するエンジン
 */
class PluginManager {
  constructor() {
    this.loadedRules = [];
    this.manifestVersion = 1;
  }

  /**
   * JSON文字列を読み込んでパースする
   * @param {string} jsonString - JSON形式の文字列
   */
  loadPlugin(jsonString) {
    try {
      const data = JSON.parse(jsonString);
      
      // バリデーション（おかしなJSONは弾く）
      if (data.manifest_version !== this.manifestVersion) {
        throw new Error('対応していないマニフェストバージョンです');
      }
      if (!Array.isArray(data.rules)) {
        throw new Error('ルールリストが見つかりません');
      }

      // ルールをメモリに展開
      data.rules.forEach(rule => {
        // 必須項目のチェック
        if (rule.type && (rule.pattern || rule.keywords)) {
          this.loadedRules.push(rule);
        }
      });

      console.log(`🧩 プラグイン読み込み完了: ${data.meta?.name} (${data.rules.length} rules)`);
      return true;

    } catch (e) {
      console.error('❌ プラグイン読み込みエラー:', e.message);
      return false;
    }
  }

  /**
   * 現在のURLやコンテンツに対して全ルールを適用し、結果を返す
   * @param {string} url - 現在のURL
   * @param {string} bodyText - ページ本文（小文字化推奨）
   */
  executeRules(url, bodyText) {
    const results = {
      score: 0,
      warnings: [],
      isAllowed: false
    };

    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    this.loadedRules.forEach(rule => {
      // ホワイトリスト判定（最強権限）
      if (rule.type === 'allowlist') {
        if (hostname.includes(rule.pattern) || hostname === rule.pattern) {
          results.isAllowed = true;
        }
        return;
      }

      // URLキーワード判定
      if (rule.type === 'url_keyword') {
        if (url.includes(rule.pattern)) {
          results.score += (rule.score || 10);
          results.warnings.push({
            title: `プラグイン検知: ${rule.id}`,
            description: rule.message || `URLに不審なパターン「${rule.pattern}」が含まれています`,
            score: rule.score
          });
        }
      }

      // 本文キーワード判定
      if (rule.type === 'dom_content') {
        // キーワードが含まれている数をカウント
        const matchCount = rule.keywords.filter(k => bodyText.includes(k)).length;
        
        // condition: 'all'なら全一致、'any'なら1つでも一致
        const isHit = (rule.condition === 'all') 
          ? matchCount === rule.keywords.length 
          : matchCount > 0;

        if (isHit) {
          results.score += (rule.score || 10);
          results.warnings.push({
            title: `プラグイン検知: ${rule.id}`,
            description: rule.message || `ページ内に不審なキーワード群を検出しました`,
            score: rule.score
          });
        }
      }
    });

    return results;
  }
}
/**
 * イベント通知クラス（コンポーネント間の通信用）
 */
class EventDispatcher {
  constructor() {
    this.listeners = new Map();
  }

  // イベント登録
  on(event, callback) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    this.listeners.get(event).push(callback);
  }

  // イベント発火
  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(callback => callback(data));
    }
  }
}

/**
 * バックエンドAPIとの通信クライアント
 */
class ApiClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
  }

  /**
   * URLの解析をリクエストする
   */
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
            // パスワード欄があるかなどの簡易情報を送る
            hasPasswordField: document.querySelectorAll('input[type="password"]').length > 0,
            formCount: document.querySelectorAll('form').length,
            scriptCount: document.querySelectorAll('script').length
          }
        })
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      // バックエンドが落ちていても拡張機能自体は止まらないようにnullを返す
      console.warn('⚠️ secutI: バックエンド接続失敗（オフラインモードで動作中）');
      return null;
    }
  }
}

// -------------------------------------------------------
// 🛡️ ホワイトリスト（信頼済みサイト）管理機能
// -------------------------------------------------------

/**
 * 現在のドメインがホワイトリスト（信頼済み）かチェックする
 * @param {Function} callback - 結果(true/false)を受け取る関数
 */
function checkIsWhitelisted(callback) {
  const domain = window.location.hostname;
  
  // Chromeのストレージからリストを取得
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['whitelist'], function(result) {
      const list = result.whitelist || [];
      const isSafe = list.includes(domain);
      callback(isSafe);
    });
  } else {
    // 開発環境などでAPIが使えない場合のフォールバック
    console.warn('SecutI: storage API not found');
    callback(false);
  }
}

/**
 * 現在のドメインをホワイトリストに追加する
 */
function addToWhitelist() {
  const domain = window.location.hostname;
  
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['whitelist'], function(result) {
      let list = result.whitelist || [];
      if (!list.includes(domain)) {
        list.push(domain);
        chrome.storage.local.set({whitelist: list}, function() {
          console.log(`SecutI: ${domain} を信頼済みリストに追加しました`);
          alert(`✅ ${domain} を信頼リストに追加しました。\nページを再読み込みして設定を反映させます。`);
          window.location.reload();
        });
      } else {
        alert('このサイトは既に信頼リストに入っています。');
      }
    });
  }
}

// -------------------------------------------------------
// 📂 ファイル解析ユーティリティ
// -------------------------------------------------------

/**
 * ファイル名からリスクレベルを判定する
 */
function analyzeFileRisk(filename) {
  if (!filename) return { level: 'unknown', label: '不明', color: '#ccc', icon: '❓' };
  
  const ext = filename.split('.').pop().toLowerCase();
  
  // 💀 超危険（実行ファイル系）
  const criticalExts = ['exe', 'msi', 'bat', 'cmd', 'sh', 'vbs', 'scr', 'com', 'js', 'jar'];
  // 📦 注意（圧縮ファイル、マクロの可能性があるOffice系）
  const warningExts = ['zip', 'rar', '7z', 'tar', 'gz', 'docm', 'xlsm', 'pptm', 'iso'];
  // 🖼️ 多分安全（画像、テキスト、PDF）
  const safeExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'mp4', 'mp3', 'wav', 'csv'];

  if (criticalExts.includes(ext)) {
    return { level: 'critical', label: '実行ファイル (高危険度)', color: '#d32f2f', icon: '💀' };
  }
  if (warningExts.includes(ext)) {
    return { level: 'warning', label: '圧縮/マクロ (中危険度)', color: '#ff9800', icon: '📦' };
  }
  if (safeExts.includes(ext)) {
    return { level: 'safe', label: 'メディア/文書 (低リスク)', color: '#4caf50', icon: '🖼️' };
  }
  
  return { level: 'unknown', label: '不明な形式', color: '#607d8b', icon: '❓' };
}

/**
 * 2つの文字列の類似度（編集距離）を計算する
 * (レーベンシュタイン距離)
 */
function getLevenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // 置換
          matrix[i][j - 1] + 1,     // 挿入
          matrix[i - 1][j] + 1      // 削除
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Internet Archiveを使って、ドメインの過去の存在を確認する
 * @param {string} domain 調査するドメイン
 * @returns {Promise<Object>} 調査結果
 */
async function checkDomainHistory(domain) {
  // 現在から計算
  const now = new Date();
  const oneYearAgo = new Date(now.getFullYear() - 1, now.getMonth(), now.getDate());
  const twoYearsAgo = new Date(now.getFullYear() - 2, now.getMonth(), now.getDate());

  // API用の日付フォーマット (YYYYMMDD)
  const formatYMD = (date) => date.toISOString().slice(0, 10).replace(/-/g, '');
  
  const timestamp1 = formatYMD(oneYearAgo);
  const timestamp2 = formatYMD(twoYearsAgo);

  try {
    // 1年前と2年前のデータを並列で問い合わせ
    const [res1, res2] = await Promise.all([
      fetch(`https://archive.org/wayback/available?url=${domain}&timestamp=${timestamp1}`),
      fetch(`https://archive.org/wayback/available?url=${domain}&timestamp=${timestamp2}`)
    ]);

    const data1 = await res1.json();
    const data2 = await res2.json();

    // スナップショットが存在するかチェック
    const exists1YearAgo = !!data1.archived_snapshots?.closest;
    const exists2YearsAgo = !!data2.archived_snapshots?.closest;

    return {
      domain: domain,
      history: {
        year1: exists1YearAgo ? data1.archived_snapshots.closest.timestamp.substring(0, 4) : null,
        year2: exists2YearsAgo ? data2.archived_snapshots.closest.timestamp.substring(0, 4) : null
      },
      isLongTerm: exists2YearsAgo // 2年以上前なら「老舗」判定
    };

  } catch (e) {
    console.error('Wayback Machine API Error:', e);
    return null; // エラー時は判定不能
  }
}