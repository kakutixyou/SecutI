// -------------------------------------------------------
// 🔍 Form Analyzer Plugin - フォーム送信先検出
// -------------------------------------------------------

class FormAnalyzerPlugin {
  constructor({ eventBus, apiClient }) {
    this.eventBus = eventBus;
    this.apiClient = apiClient;
  }

  /**
   * フォームの送信先とセキュリティリスクを解析
   */
  async analyze(context) {
    const forms = document.querySelectorAll('form');
    
    if (forms.length === 0) {
      return null;
    }

    const results = {
      pluginId: 'form-analyzer',
      score: 0,
      severity: 'info',
      reasons: [],
      metadata: {
        forms: [],
        totalFormCount: forms.length
      }
    };

    // 各フォームを解析
    forms.forEach((form, index) => {
      const formData = this._analyzeForm(form, index);
      results.metadata.forms.push(formData);

      // リスクスコアの計算
      if (formData.risks.length > 0) {
        results.score += formData.riskScore;
        results.reasons.push(...formData.risks);
      }
    });

    // 深刻度の判定
    if (results.score >= 50) {
      results.severity = 'high';
    } else if (results.score >= 30) {
      results.severity = 'medium';
    } else if (results.score > 0) {
      results.severity = 'low';
    }

    // DevTools風の詳細情報を生成
    if (results.metadata.forms.length > 0) {
      this._logToConsole(results.metadata.forms);
    }

    return results.score > 0 ? results : null;
  }

  /**
   * 個別のフォームを解析
   */
  _analyzeForm(form, index) {
    const formData = {
      index: index + 1,
      action: form.action || window.location.href,
      method: form.method || 'GET',
      target: form.target || '_self',
      fields: [],
      risks: [],
      riskScore: 0
    };

    // フィールドを取得
    const inputs = form.querySelectorAll('input, textarea, select');
    inputs.forEach(input => {
      const fieldInfo = {
        type: input.type || 'text',
        name: input.name || '(unnamed)',
        required: input.required,
        pattern: input.pattern || null
      };

      // パスワードフィールドの検出
      if (input.type === 'password') {
        fieldInfo.isPassword = true;
      }

      // メールフィールドの検出
      if (input.type === 'email' || input.name.toLowerCase().includes('email')) {
        fieldInfo.isEmail = true;
      }

      // クレジットカード番号の可能性
      if (this._isCreditCardField(input)) {
        fieldInfo.isCreditCard = true;
      }

      formData.fields.push(fieldInfo);
    });

    // リスク評価
    this._evaluateFormRisks(formData);

    return formData;
  }

  /**
   * フォームのリスクを評価
   */
  _evaluateFormRisks(formData) {
    const actionUrl = formData.action;
    const currentDomain = window.location.hostname;

    // 1. 外部サイトへの送信
    if (this._isExternalUrl(actionUrl)) {
      const targetDomain = new URL(actionUrl).hostname;
      formData.risks.push(
        `データ送信先が外部サイトです: ${targetDomain}`
      );
      formData.riskScore += 25;
    }

    // 2. HTTPでの送信（暗号化なし）
    if (actionUrl.startsWith('http://')) {
      formData.risks.push(
        'HTTP経由で送信されます（暗号化されていません）'
      );
      formData.riskScore += 35;
    }

    // 3. パスワードフィールドがある
    const hasPassword = formData.fields.some(f => f.isPassword);
    if (hasPassword) {
      formData.risks.push(
        'パスワード入力欄が検出されました'
      );
      formData.riskScore += 20;

      // HTTPとパスワードの組み合わせは特に危険
      if (actionUrl.startsWith('http://')) {
        formData.risks.push(
          '⚠️ 危険: パスワードが暗号化されずに送信されます'
        );
        formData.riskScore += 30;
      }
    }

    // 4. クレジットカード情報
    const hasCreditCard = formData.fields.some(f => f.isCreditCard);
    if (hasCreditCard) {
      formData.risks.push(
        'クレジットカード情報の入力欄が検出されました'
      );
      formData.riskScore += 30;
    }

    // 5. メールアドレス
    const hasEmail = formData.fields.some(f => f.isEmail);
    if (hasEmail) {
      formData.risks.push(
        'メールアドレスの入力が要求されています'
      );
      formData.riskScore += 10;
    }

    // 6. POSTメソッドなのにGET
    if (formData.method.toUpperCase() === 'GET' && (hasPassword || hasCreditCard)) {
      formData.risks.push(
        '機密情報がURLに露出する可能性があります（GETメソッド）'
      );
      formData.riskScore += 20;
    }

    // 7. JavaScriptでの送信（action属性なし）
    if (!formData.action || formData.action === window.location.href) {
      formData.risks.push(
        'JavaScriptで送信処理が行われている可能性があります'
      );
      formData.riskScore += 15;
    }
  }

  /**
   * クレジットカードフィールドかどうかを判定
   */
  _isCreditCardField(input) {
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const placeholder = (input.placeholder || '').toLowerCase();

    const ccKeywords = [
      'card', 'cc', 'credit', 'cvv', 'cvc', 'ccv',
      'cardnumber', 'card-number', 'creditcard'
    ];

    return ccKeywords.some(keyword => 
      name.includes(keyword) || id.includes(keyword) || placeholder.includes(keyword)
    );
  }

  /**
   * 外部URLかどうかを判定
   */
  _isExternalUrl(url) {
    try {
      const currentDomain = window.location.hostname;
      const targetUrl = new URL(url, window.location.origin);
      return targetUrl.hostname !== currentDomain;
    } catch {
      return false;
    }
  }

  /**
   * DevTools風にコンソールに出力
   */
  _logToConsole(forms) {
    console.group('🔍 secutI: フォーム送信先の検出');
    
    forms.forEach(form => {
      console.group(`フォーム #${form.index}`);
      
      // 送信先の表示
      console.log('%c送信先URL:', 'font-weight: bold; color: #667eea;');
      console.log(`  ${form.action}`);
      
      // メソッドとターゲット
      console.log('%cメソッド:', 'font-weight: bold;', form.method.toUpperCase());
      console.log('%cターゲット:', 'font-weight: bold;', form.target);
      
      // 入力フィールド
      if (form.fields.length > 0) {
        console.group(`入力フィールド (${form.fields.length}個)`);
        form.fields.forEach(field => {
          let typeLabel = field.type;
          if (field.isPassword) typeLabel += ' 🔑';
          if (field.isEmail) typeLabel += ' 📧';
          if (field.isCreditCard) typeLabel += ' 💳';
          
          console.log(`  [${typeLabel}] ${field.name}${field.required ? ' (必須)' : ''}`);
        });
        console.groupEnd();
      }
      
      // リスク
      if (form.risks.length > 0) {
        console.group('%c⚠️ 検出されたリスク', 'color: red; font-weight: bold;');
        form.risks.forEach(risk => {
          console.warn(`  • ${risk}`);
        });
        console.groupEnd();
      }
      
      console.groupEnd();
    });
    
    console.log('%c💡 ヒント: Ctrl+Shift+I でこの情報を確認できます', 'color: #999; font-style: italic;');
    console.groupEnd();
  }

  /**
   * クリーンアップ
   */
  destroy() {
    // リソース解放
  }
}

// エクスポート
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FormAnalyzerPlugin;
}