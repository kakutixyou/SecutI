// -------------------------------------------------------
// 🛡️ secutI - popup.js (Mod System Supported)
// フィッシング対策 + 強制遮断 + Mod読み込み
// -------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  console.log('🔧 Popup initialized');

  // =================================================================
  // 1. DOM要素の取得
  // =================================================================
  const getEl = (id) => document.getElementById(id);

  const ui = {
    // タブ関連
    tabs: document.querySelectorAll('.tab-btn'),
    panels: {
      'status': getEl('panel-status'),
      'settings': getEl('panel-settings')
    },
    // ステータス表示エリア
    domainDisplay: getEl('domain-display'),
    historyArea: getEl('history-area'),
    warningList: getEl('warning-list'),
    linkGoogle: getEl('link-google'),
    linkWhois: getEl('link-whois'),
    
    // 設定スイッチ
    togglePhishing: getEl('toggle-phishing'),
    toggleScript: getEl('toggle-script'),
    toggleDbd: getEl('toggle-dbd'),
    
    // ログ出力ボタン
    btnExport: getEl('btn-export-logs'),

    // ★★★ Modインポート用要素 (追加) ★★★
    btnImportMod: getEl('btn-import-mod'),
    fileInput: getEl('mod-file-input'),
    modStatus: getEl('mod-status')
  };

  // =================================================================
  // 2. 初期化処理
  // =================================================================
  setupTabs();
  loadSettings();
  loadAnalysisData();
  setupModImporter(); // ★★★ Mod機能のセットアップ呼び出し

  // =================================================================
  // 3. タブ切り替えロジック
  // =================================================================
  function setupTabs() {
    ui.tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        ui.tabs.forEach(t => t.classList.remove('active'));
        Object.values(ui.panels).forEach(p => p && p.classList.remove('active'));

        tab.classList.add('active');
        const targetId = tab.dataset.target;
        if (ui.panels[targetId]) {
          ui.panels[targetId].classList.add('active');
        }
      });
    });
  }

  // =================================================================
  // 4. 設定読み込み & スイッチ制御
  // =================================================================
  async function loadSettings() {
    try {
      const result = await chrome.storage.local.get(['enablePhishing', 'enableScript', 'enableDbd']);

      if (ui.togglePhishing) {
        ui.togglePhishing.checked = result.enablePhishing !== false;
        ui.togglePhishing.addEventListener('change', async (e) => {
          await chrome.storage.local.set({ enablePhishing: e.target.checked });
        });
      }

      if (ui.toggleScript) {
        ui.toggleScript.checked = result.enableScript !== false;
        ui.toggleScript.addEventListener('change', async (e) => {
          await chrome.storage.local.set({ enableScript: e.target.checked });
        });
      }

      if (ui.toggleDbd) {
        ui.toggleDbd.checked = result.enableDbd === true;
        ui.toggleDbd.addEventListener('change', async (e) => {
          const enabled = e.target.checked;
          if (enabled) {
            const confirmed = confirm(
              '⚠️ 完全遮断モードを有効にしますか？\n\n' +
              '全てのダウンロードがブロックされます。'
            );
            if (!confirmed) {
              e.target.checked = false;
              return;
            }
          }
          await chrome.storage.local.set({ enableDbd: enabled });
        });
      }
    } catch (error) {
      console.error('❌ 設定読み込みエラー:', error);
    }
  }

  // =================================================================
  // 5. ステータスレポート表示機能
  // =================================================================
  function loadAnalysisData() {
    chrome.storage.local.get(['lastAnalysis'], (result) => {
      const data = result.lastAnalysis;
      if (data) {
       // updateStatusUI(data);
        checkModRulesForPopup(domain, tabs[0].url);
      } else {
        if(ui.domainDisplay) ui.domainDisplay.innerText = "No Data";
      }
    });

    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (!tabs[0]?.url) return;
      try {
        const url = new URL(tabs[0].url);
        const domain = url.hostname;

        if (domain === 'localhost' || domain.includes('127.0.0.1') || !domain.includes('.')) {
           if(ui.domainDisplay) ui.domainDisplay.innerText = domain + " (Local)";
           return;
        }

        if(ui.domainDisplay) ui.domainDisplay.innerText = domain;
        if(ui.linkGoogle) ui.linkGoogle.href = `https://www.google.com/search?q=site:${domain}`;
        if(ui.linkWhois) ui.linkWhois.href = `https://www.whois.com/whois/${domain}`;

        if(ui.historyArea) ui.historyArea.style.opacity = '0.5';
        const historyResult = await checkDomainHistory(domain);
        if(ui.historyArea) ui.historyArea.style.opacity = '1';
        updateHistoryUI(historyResult);

      } catch (e) { console.error(e); }
    });
  }

  function updateStatusUI(data) {
    if (!ui.warningList) return;
    ui.warningList.innerHTML = '';
    if (data.warnings && data.warnings.length > 0) {
      data.warnings.forEach(w => {
        const div = document.createElement('div');
        div.className = 'warning-item';
        div.innerHTML = `
          <span style="font-size:16px;">${w.icon || '⚠️'}</span>
          <div>
            <div style="font-weight:bold; color:#333;">${w.title}</div>
            <div style="font-size:11px; color:#666;">${w.description}</div>
          </div>
        `;
        ui.warningList.appendChild(div);
      });
    } else {
      ui.warningList.innerHTML = '<div class="no-warnings">✅ Clean. No threats detected.</div>';
    }
  }

  function updateHistoryUI(data) {
    if (!data || !data.history) return;
    const el1y = document.getElementById('hist-1y');
    const el2y = document.getElementById('hist-2y');
    if (!el1y || !el2y) return;

    const updateBadge = (el, exists) => {
      if (exists) {
        el.textContent = '✅ Exists';
        el.className = 'history-badge badge-safe';
      } else {
        el.textContent = '❌ None';
        el.className = 'history-badge badge-warn';
      }
    };
    updateBadge(el1y, data.history.year1);
    updateBadge(el2y, data.history.year2);
  }

  // =================================================================
  // 6. ログ出力機能
  // =================================================================
  if (ui.btnExport) {
    ui.btnExport.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'exportLogs' }, (response) => {
        if (chrome.runtime.lastError || !response || !response.logs) {
           alert('ログがありません。'); return; 
        }
        const blob = new Blob([JSON.stringify(response.logs, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        chrome.downloads.download({ url: url, filename: 'SecutI.json', saveAs: true });
      });
    });
  }

  // =================================================================
  // ★★★ 7. Modインポート機能 (新規追加) ★★★
  // =================================================================
  function setupModImporter() {
    if (!ui.btnImportMod || !ui.fileInput) return;

    // ボタンを押したら、隠れたinput要素をクリックさせる
    ui.btnImportMod.addEventListener('click', () => {
      ui.fileInput.click();
    });

    // ファイルが選択されたら実行
    ui.fileInput.addEventListener('change', (event) => {
      const file = event.target.files[0];
      if (!file) return;

      const reader = new FileReader();

      // ファイル読み込み完了時の処理
      reader.onload = async (e) => {
        try {
          // JSONとして解析
          const jsonContent = JSON.parse(e.target.result);

          // 簡易バリデーション (rules配列があるか確認)
          if (!jsonContent.rules || !Array.isArray(jsonContent.rules)) {
            throw new Error('形式エラー: "rules" リストが見つかりません');
          }

          // ストレージに保存 (既存のModに追加する場合はロジックを変えるが、今回は上書き)
          // "secutiConfig" の中にマージするのが理想的
          const currentSettings = await chrome.storage.local.get('secutiConfig');
          let newConfig = currentSettings.secutiConfig || {};

          // Modの内容を結合 (ここではwhitelistに追加する例。本来はMod専用領域が望ましい)
          // ⚠️ 実際には background.js 側でこのModデータを解釈するロジックが必要
          
          // とりあえず "userMod" というキーで保存
          await chrome.storage.local.set({ userMod: jsonContent });

          // 成功メッセージ
          const modName = jsonContent.name || '不明なMod';
          ui.modStatus.style.color = 'green';
          ui.modStatus.innerText = `✅ Mod読み込み成功: ${modName}`;

          // 設定が変更されたことを通知（必要なら）
          // chrome.runtime.sendMessage({ action: 'modLoaded', data: jsonContent });

        } catch (err) {
          console.error(err);
          ui.modStatus.style.color = 'red';
          ui.modStatus.innerText = `❌ エラー: ${err.message}`;
        }
      };

      // テキストとして読み込む
      reader.readAsText(file);
      
      // 同じファイルを連続で選べるようにリセット
      ui.fileInput.value = '';
    });
  }
});

// =================================================================
// 8. ヘルパー関数: ドメイン履歴API
// =================================================================
async function checkDomainHistory(domain) {
  const now = new Date();
  const formatYMD = (date) => date.toISOString().slice(0, 10).replace(/-/g, '');
  try {
    const [res1, res2] = await Promise.all([
      fetch(`https://archive.org/wayback/available?url=${domain}&timestamp=${formatYMD(new Date(now.getFullYear() - 1, now.getMonth(), now.getDate()))}`),
      fetch(`https://archive.org/wayback/available?url=${domain}&timestamp=${formatYMD(new Date(now.getFullYear() - 2, now.getMonth(), now.getDate()))}`)
    ]);
    const data1 = await res1.json();
    const data2 = await res2.json();
    return {
      history: {
        year1: !!data1.archived_snapshots?.closest,
        year2: !!data2.archived_snapshots?.closest
      }
    };
  } catch (e) { return null; }
}