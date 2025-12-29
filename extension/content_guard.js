// -------------------------------------------------------
// 🛡️ secutI - content_guard.js (Monitor Mode)
// ユーザー操作の監視と、過剰な連打の抑制
// -------------------------------------------------------

(() => {
  'use strict';

  const MAX_AUTO_LINKS = 5;       // 連打の許容数
  const OBSERVE_WINDOW_MS = 3000; // 監視時間

  let autoLinkCount = 0;
  let lastUserGesture = 0;

  // -----------------------------
  // ユーザー操作の記録
  // -----------------------------
  ['click', 'keydown', 'touchstart'].forEach(evt => {
    window.addEventListener(evt, () => {
      lastUserGesture = Date.now();
    }, { capture: true, passive: true });
  });

  // 直近1秒以内にユーザー操作があったか？
  function hasRecentUserGesture() {
    return Date.now() - lastUserGesture < 1000;
  }

  // -----------------------------
  // リンク監視 (破壊せず、監視だけする)
  // -----------------------------
  function inspectAnchor(anchor) {
    if (!anchor || anchor.dataset.secutiChecked) return;
    anchor.dataset.secutiChecked = 'true';

    // ★重要変更: リンクを無効化せず、異常な連打だけを止める
    if (anchor.hasAttribute('download')) {
      // ユーザー操作なし、かつ短時間に大量発生している場合のみ止める
      if (!hasRecentUserGesture()) {
        autoLinkCount++;
        if (autoLinkCount > MAX_AUTO_LINKS) {
          console.warn('🛡️ secutI: ダウンロードスパムを検知し、リンクを無効化しました');
          anchor.href = 'javascript:void(0)';
          anchor.style.pointerEvents = 'none';
          anchor.removeAttribute('download');
        }
      }
    }
  }

  // -----------------------------
  // MutationObserver
  // -----------------------------
  const observer = new MutationObserver(mutations => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        if (node.tagName === 'A') {
          inspectAnchor(node);
        } else {
          node.querySelectorAll?.('a').forEach(inspectAnchor);
        }
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  // -----------------------------
  // window.open 対策
  // -----------------------------
  const originalOpen = window.open;
  window.open = function (...args) {
    // ユーザー操作なしの連打は止めるが、1回目は通す（background.jsに任せるため）
    if (!hasRecentUserGesture() && autoLinkCount > 2) {
      console.warn('🛡️ secutI: ユーザー操作のない window.open を遮断');
      return null;
    }
    if (!hasRecentUserGesture()) autoLinkCount++;
    return originalOpen.apply(window, args);
  };

  // カウンタリセット
  setInterval(() => {
    autoLinkCount = 0;
  }, OBSERVE_WINDOW_MS);

  console.log('🛡️ secutI: content_guard.js (Monitor Mode) 有効');
})();