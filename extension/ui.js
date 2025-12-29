// -------------------------------------------------------
// 🎨 ui.js
// 警告画面の描画・制御を担当するモジュール
// Shadow DOM技術により、Webサイト側のCSSと完全に分離して表示を行う
// -------------------------------------------------------

class UIController {
  constructor() {
    // IDをランダム化して、サイト側からの特定・削除を難しくする
    this.randomId = 'secuti-ui-' + Math.random().toString(36).substring(2) + Date.now().toString(36);
    this.shadowRoot = null;
    this.hostElement = null;
  }

  /**
   * 解析結果に基づき、セキュリティレポート（警告オーバーレイ）を表示する
   * @param {Object} analysisData - 解析結果オブジェクト
   */
  showWarning(analysisData) {
    // 既に表示済みなら何もしない
    if (document.getElementById(this.randomId)) return;

    // ※ 表示するかどうかの判断ロジックは main.js 側に移行しましたが、
    //念のため空データの場合は弾く
    if (!analysisData || !analysisData.analysis) return;

    console.warn(`⚠️ secutI: 警告レポートを表示します`);

    // 1. ホスト要素（Shadow DOMの親）を作成
    this.hostElement = document.createElement('div');
    this.hostElement.id = this.randomId;
    
    // サイト側のCSSリセット（最強のリセット設定）
    // pointer-events: none にしておき、中身のコンテナだけ auto に戻すことで
    // 万が一の表示崩れ時もサイト操作を完全にブロックしきらないようにする保険
    this.hostElement.style.cssText = `
      all: initial;
      display: block;
      position: fixed;
      top: 0;
      left: 0;
      width: 0;
      height: 0;
      border: none;
      z-index: 2147483647; /* 32bit整数の最大値 */
      pointer-events: none;
    `;

    // 2. Shadow DOMを 'closed' モードで作成（外部JSからのアクセス遮断）
    this.shadowRoot = this.hostElement.attachShadow({ mode: 'closed' });

    // 3. スタイルとコンテンツを作成
    const styleElement = this._createStyles();
    const contentElement = this._createOverlayContent(analysisData);

    // 4. Shadow DOMに封入
    this.shadowRoot.appendChild(styleElement);
    this.shadowRoot.appendChild(contentElement);

    // 5. ページに挿入
    document.body.appendChild(this.hostElement);

    // 6. ボタン等のイベントリスナーを設定
    this._attachEventListeners(analysisData);
  }

  /**
   * 警告画面を削除する
   */
  hideWarning() {
    this.hostElement?.remove();
    this.hostElement = null;
    this.shadowRoot = null;
    console.log('✅ secutI: オーバーレイを閉じました');
  }

  // -------------------------------------------------------
  // 内部メソッド (Private-like methods)
  // -------------------------------------------------------

  /**
   * Shadow DOM内のCSSを作成
   * スコア表示用ではなく、レポート表示用にデザインを一新
   */
  _createStyles() {
    const style = document.createElement('style');
    style.textContent = `
      /* ホストが pointer-events: none なので、中身は auto に戻す */
      .overlay-container {
        pointer-events: auto; 
        position: fixed; 
        top: 0; 
        left: 0; 
        width: 100%;
        height: 100%; 
        background: rgba(0, 0, 0, 0.85); /* 背景を少し落ち着いた色に */
        display: flex; 
        justify-content: center; 
        align-items: center;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        backdrop-filter: blur(5px);
        animation: fadeIn 0.3s ease-out;
        z-index: 2147483647;
        box-sizing: border-box;
      }
      
      * { box-sizing: border-box; }

      @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
      @keyframes slideUp { from { transform: translateY(30px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

      .card {
        background: #fff; 
        padding: 0;
        border-radius: 12px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.5); 
        width: 90%; 
        max-width: 650px; 
        max-height: 90vh;
        overflow-y: auto; 
        animation: slideUp 0.4s ease-out;
        color: #333;
        text-align: left;
        display: flex;
        flex-direction: column;
      }

      .report-header {
        padding: 20px 25px;
        background: #f8f9fa;
        border-bottom: 1px solid #eaeaea;
        display: flex;
        align-items: center;
        gap: 15px;
        border-radius: 12px 12px 0 0;
      }

      .header-icon { font-size: 32px; }
      .header-text h2 { margin: 0; font-size: 18px; color: #2c3e50; }
      .header-text p { margin: 2px 0 0 0; font-size: 12px; color: #7f8c8d; }

      .content-body {
        padding: 25px;
      }

      .section-title {
        font-size: 13px;
        font-weight: 700;
        color: #555;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        gap: 5px;
      }

      /* 警告リストのデザイン */
      .warning-list {
        background: #fff;
        max-height: 300px;
        overflow-y: auto;
        margin-bottom: 25px;
      }

      .warning-item {
        padding: 12px 15px;
        margin-bottom: 10px;
        background: #fdfdfd;
        border: 1px solid #eee;
        border-left-width: 4px; /* ここに色がつく */
        border-radius: 4px;
        transition: transform 0.2s;
      }
      .warning-item:hover { transform: translateX(2px); }

      .warning-title { font-weight: bold; font-size: 14px; color: #333; display: flex; align-items: center; gap: 6px; }
      .warning-desc { margin-top: 5px; font-size: 13px; color: #666; line-height: 1.5; }

      /* 調査ツールのデザイン */
      .tools-area {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 20px;
        border: 1px dashed #ddd;
      }
      .tools-grid {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
      }
      .tool-btn {
        text-decoration: none;
        background: #fff;
        color: #444;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        display: flex;
        align-items: center;
        gap: 6px;
        border: 1px solid #ddd;
        transition: all 0.2s;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
      }
      .tool-btn:hover { background: #f0f0f0; border-color: #ccc; }

      /* ボタンエリア */
      .btn-group { 
        display: flex; 
        gap: 12px; 
        padding-top: 10px;
        border-top: 1px solid #eee;
        flex-wrap: wrap;
      }
      
      .btn {
        flex: 1; 
        padding: 12px; 
        border: none; 
        border-radius: 6px;
        font-size: 14px; 
        font-weight: 600; 
        cursor: pointer; 
        transition: all 0.2s;
        display: flex; align-items: center; justify-content: center; gap: 6px;
        min-width: 140px;
      }
      
      .btn:active { transform: scale(0.98); }

      .btn-back { background: #e74c3c; color: white; }
      .btn-back:hover { background: #c0392b; }
      
      .btn-whitelist { background: #2ecc71; color: white; }
      .btn-whitelist:hover { background: #27ae60; }
      
      .btn-proceed { background: transparent; border: 1px solid #ccc; color: #7f8c8d; }
      .btn-proceed:hover { background: #f5f5f5; color: #333; }

      .footer {
        padding: 10px 25px;
        background: #fafafa;
        border-top: 1px solid #eee;
        text-align: center;
        border-radius: 0 0 12px 12px;
      }
      .btn-dev { 
        background: none; border: none; color: #aaa; font-size: 11px; cursor: pointer; text-decoration: underline;
      }
    `;
    return style;
  }

  /**
   * HTML構造の作成（レポート形式）
   */
  _createOverlayContent(analysisData) {
    const analysis = analysisData.analysis || {};
    // スコアはもう表示しない（内部ロジックでのみ使用）
    // const score = analysis.totalScore || 0; 
    
    const severity = analysis.severity || 'info';
    const warnings = analysis.warnings || [];

    // 深刻度に応じた色とアイコン設定
    const config = {
      critical: { icon: '🚨', color: '#e74c3c', text: '重大なリスク検知' },
      high:     { icon: '🛑', color: '#e67e22', text: '高リスク検知' },
      medium:   { icon: '⚠️', color: '#f1c40f', text: '注意が必要' },
      low:      { icon: 'ℹ️', color: '#3498db', text: '確認事項あり' },
      info:     { icon: '📝', color: '#95a5a6', text: '解析レポート' }
    }[severity] || { icon: '📝', color: '#95a5a6', text: '解析レポート' };

    // 1. 警告リストのHTML生成
    const warningListHTML = warnings.length > 0 ? warnings.map(w => `
      <div class="warning-item" style="border-left-color: ${config.color};">
        <div class="warning-title">${w.icon || '⚠️'} ${w.title}</div>
        <div class="warning-desc">
          ${w.description}
        </div>
      </div>
    `).join('') : '<div style="padding:15px; color:#999; text-align:center;">特筆すべきリスク要因は見つかりませんでした。<br>安全性が高いか、まだ検知されていない新しい脅威の可能性があります。</div>';

    // 2. 調査ツールリンクの生成
    const currentDomain = window.location.hostname;
    // google検索用URL生成（安全のためエンコード）
    const searchUrl = `https://www.google.com/search?q=site:${currentDomain}`;
    const waybackUrl = `https://web.archive.org/web/*/${currentDomain}`;
    const vtUrl = `https://www.virustotal.com/gui/domain/${currentDomain}`;

    const container = document.createElement('div');
    container.className = 'overlay-container';
    
    container.innerHTML = `
      <div class="card">
        <div class="report-header">
          <div class="header-icon">${config.icon}</div>
          <div class="header-text">
            <h2>SecutI Security Report</h2>
            <p>このサイトの解析結果・判断材料を表示しています</p>
          </div>
        </div>

        <div class="content-body">
          
          <div class="section-title">🔍 Detection Findings (判断材料)</div>
          <div class="warning-list">
            ${warningListHTML}
          </div>

          <div class="tools-area">
            <div class="section-title" style="margin-top:0;">🛠️ Investigation Tools (外部調査)</div>
            <div class="tools-grid">
              <a href="${searchUrl}" target="_blank" class="tool-btn">
                 🔍 Googleインデックス確認
              </a>
              <a href="${waybackUrl}" target="_blank" class="tool-btn">
                 📅 過去の運営歴 (Wayback)
              </a>
              <a href="${vtUrl}" target="_blank" class="tool-btn">
                 🛡️ VirusTotalスキャン
              </a>
            </div>
            <div style="margin-top:8px; font-size:11px; color:#888;">
              ※ リンク先は外部サイトです。このサイトのドメイン情報を確認できます。
            </div>
          </div>

          <div class="btn-group">
            <button class="btn btn-back" id="btn-back">
              <span>🔙 安全策をとって戻る</span>
            </button>
            
            <button class="btn btn-whitelist" id="btn-whitelist">
              <span>✅ このサイトを信頼する</span>
            </button>
            
            <button class="btn btn-proceed" id="btn-proceed">
              <span>判断して進む (閉じる)</span>
            </button>
          </div>
        </div>

        <div class="footer">
          <button class="btn-dev" id="btn-devtools">Developer Console Log</button>
        </div>
      </div>
    `;
    return container;
  }

  /**
   * ボタンのイベントリスナー設定
   */
  _attachEventListeners(analysisData) {
    const shadow = this.shadowRoot;

    // 「戻る」ボタン
    shadow.getElementById('btn-back')?.addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close(); // 履歴がない場合は閉じる試み
      }
    });

    // 「進む（閉じる）」ボタン
    shadow.getElementById('btn-proceed')?.addEventListener('click', () => {
      this.hideWarning();
    });

    // 「ホワイトリスト追加」ボタン
    shadow.getElementById('btn-whitelist')?.addEventListener('click', () => {
      // utils.js の関数を呼び出す
      if (typeof addToWhitelist === 'function') {
        addToWhitelist(); 
      } else {
        // フォールバック（直接実装）
        const domain = window.location.hostname;
        // eslint-disable-next-line no-undef
        chrome.storage.local.get(['whitelist'], function(result) {
            let list = result.whitelist || [];
            if (!list.includes(domain)) {
                list.push(domain);
                // eslint-disable-next-line no-undef
                chrome.storage.local.set({whitelist: list}, function() {
                    alert(`✅ ${domain} を信頼リストに追加しました。\nページをリロードします。`);
                    window.location.reload();
                });
            }
        });
      }
      this.hideWarning();
    });

    // 「DevTools詳細」ボタン
    shadow.getElementById('btn-devtools')?.addEventListener('click', () => {
      console.group('🔍 secutI: Detailed Report');
      console.log('Full Analysis Data:', analysisData);
      console.groupEnd();
      alert('F12キー (開発者ツール) の「Console」タブに詳細を出力しました。');
    });
  }

  // -------------------------------------------------------
  // ダウンロード警告機能 (スコア非依存の独立機能)
  // -------------------------------------------------------

  /**
   * ダウンロード警告を表示する
   * @param {Array} downloads - ダウンロード情報の配列
   */
  showDownloadAlert(downloads) {
    if (downloads.length === 0) return;

    if (document.getElementById(this.randomId)) {
      this.hideWarning();
    }

    this.hostElement = document.createElement('div');
    this.hostElement.id = this.randomId;
    this.hostElement.style.cssText = `
      all: initial; position: fixed; top: 0; left: 0; width: 0; height: 0; z-index: 2147483647;
    `;
    this.shadowRoot = this.hostElement.attachShadow({ mode: 'closed' });
    this.shadowRoot.appendChild(this._createStyles());

    // リスト生成
    const listHtml = downloads.map(d => {
      const fileName = d.filename ? d.filename.split(/[/\\]/).pop() : 'ファイル名取得中...';
      // utils.js の analyzeFileRisk を使用 (なければ簡易判定)
      const risk = (typeof analyzeFileRisk === 'function') 
        ? analyzeFileRisk(fileName) 
        : { level: 'unknown', label: '未解析', color: '#999', icon: '❓' };

      const bgColor = risk.level === 'critical' ? '#ffebee' : 
                      risk.level === 'safe' ? '#e8f5e9' : '#fff3e0';

      return `
        <div class="warning-item" style="background: ${bgColor}; border-left-color: ${risk.color}; display: flex; flex-direction: column; gap: 10px;">
          
          <div style="display:flex; justify-content:space-between; align-items:start;">
            <div>
              <div style="font-size: 15px; font-weight: bold; color: #333;">
                ${risk.icon} ${fileName}
              </div>
              <div style="font-size:11px; color:${risk.color}; font-weight:bold; margin-top:4px;">
                判定: ${risk.label}
              </div>
              <div style="font-size:10px; color:#666; margin-top:2px;">
                ID: ${d.id} | サイズ: ${d.fileSize ? (d.fileSize / 1024).toFixed(1) + ' KB' : '不明'}
              </div>
            </div>
          </div>

          <div style="display:flex; gap: 10px; width: 100%;">
            <button class="btn-keep" data-id="${d.id}" style="
              flex: 1; background: #2ecc71; color: white; border: none; padding: 8px; 
              border-radius: 4px; cursor: pointer; font-weight: bold; font-size:12px;">
              ✅ 安全 (保存)
            </button>
            
            <button class="btn-delete" data-id="${d.id}" style="
              flex: 1; background: #e74c3c; color: white; border: none; padding: 8px; 
              border-radius: 4px; cursor: pointer; font-weight: bold; font-size:12px;">
              🗑️ 危険 (即削除)
            </button>
          </div>

        </div>
      `;
    }).join('');

    const container = document.createElement('div');
    container.className = 'overlay-container';
    
    // 全体の枠組み
    container.innerHTML = `
      <div class="card" style="border-top: 5px solid #e74c3c;">
        <div class="report-header" style="background: #fff5f5;">
          <div class="header-icon">📥</div>
          <div class="header-text">
            <h2>Download Alert</h2>
            <p>意図しないファイルのダウンロードを検知しました</p>
          </div>
        </div>

        <div class="content-body">
          <div class="warning-list" style="max-height: 400px;">
            ${listHtml}
          </div>

          <div class="footer" style="margin-top:0; border-top:none; background:transparent;">
             <button class="btn btn-proceed" id="btn-close-dl" style="width:100%;">
               とりあえず閉じる (判断保留)
             </button>
          </div>
        </div>
      </div>
    `;

    this.shadowRoot.appendChild(container);
    document.body.appendChild(this.hostElement);

    // --- イベント設定 ---

    // 🗑️ 削除ボタン
    const deleteBtns = this.shadowRoot.querySelectorAll('.btn-delete');
    deleteBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = parseInt(e.target.dataset.id);
        if(confirm('本当にこのファイルを削除しますか？\n(復元できません)')) {
          // eslint-disable-next-line no-undef
          chrome.runtime.sendMessage({ action: 'DELETE_FILE', downloadId: id }, (res) => {
            if (res && res.success) {
              e.target.closest('.warning-item').remove();
              // 全部消えたらウィンドウも閉じる
              if (this.shadowRoot.querySelectorAll('.warning-item').length === 0) {
                this.hideWarning();
              }
            } else {
              alert('❌ 削除失敗: ファイルが既にない可能性があります');
            }
          });
        }
      });
    });

    // ✅ 安全（保存）ボタン
    const keepBtns = this.shadowRoot.querySelectorAll('.btn-keep');
    keepBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const item = e.target.closest('.warning-item');
        item.style.opacity = '0.5';
        item.innerHTML = '<div style="padding:10px; text-align:center; color:#27ae60; font-weight:bold;">✅ 保存しました</div>';
        setTimeout(() => item.remove(), 800);
        // 全部消えたらウィンドウも閉じる
        setTimeout(() => {
           if (this.shadowRoot && this.shadowRoot.querySelectorAll('.warning-item').length === 0) {
             this.hideWarning();
           }
        }, 900);
      });
    });

    // 閉じるボタン
    this.shadowRoot.getElementById('btn-close-dl')?.addEventListener('click', () => {
      this.hideWarning();
    });
  }
}