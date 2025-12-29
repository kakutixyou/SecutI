// -------------------------------------------------------
// 🎭 impersonation.js
// 有名ブランド（Zoom, Amazon等）のなりすまし検知モジュール
// -------------------------------------------------------

 class ImpersonationDetector {
  constructor() {
    // ブランド名と正規ドメインのペア
    this.protectedBrands = {
      'zoom': ['zoom.us', 'zoom.com', 'zoom.gov'],
      'microsoft': ['microsoft.com', 'live.com', 'office.com', 'sharepoint.com', 'microsoftonline.com'],
      'google': ['google.com', 'accounts.google.com', 'youtube.com', 'gmail.com'],
      'amazon': ['amazon.co.jp', 'amazon.com'],
      'rakuten': ['rakuten.co.jp', 'rakuten.ne.jp'],
      'teams': ['microsoft.com', 'teams.live.com'],
      'dropbox': ['dropbox.com'],
      'docomo': ['docomo.ne.jp', 'nttdocomo.co.jp']
    };
  }

  /**
   * 現在のページがなりすましかどうかチェックする
   * @returns {Object|null} 検知された場合は警告オブジェクト、なければnull
   */
  check() {
    const currentDomain = window.location.hostname;
    const pageTitle = document.title.toLowerCase();
    
    // パフォーマンスのため、本文のチェックは最初の2000文字のみ
    const bodyText = document.body.innerText.substring(0, 2000).toLowerCase();
    
    // パスワード入力欄がないページ（ただのブログなど）は誤検知防止のため除外
    const hasPasswordInput = document.querySelector('input[type="password"]');
    if (!hasPasswordInput) return null;

    for (const [brand, safeDomains] of Object.entries(this.protectedBrands)) {
      // ページタイトルや本文にブランド名が含まれているか？
      if (pageTitle.includes(brand) || bodyText.includes(brand)) {
        
        // 現在のドメインが正規リストに含まれているか確認
        // (サブドメインも考慮して後方一致でチェック)
        const isSafe = safeDomains.some(safe => 
          currentDomain === safe || currentDomain.endsWith('.' + safe)
        );

        // ブランド名があるのに正規ドメインじゃない場合
        if (!isSafe) {
          return {
            detected: true,
            brand: brand,
            currentDomain: currentDomain,
            score: 70, // かなり高い危険度
            severity: 'critical',
            reason: `このサイトは ${brand.toUpperCase()} を装っている可能性がありますが、URLが公式のものではありません。`
          };
        }
      }
    }

    return null;
  }
}