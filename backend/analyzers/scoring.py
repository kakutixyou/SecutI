"""
複数の解析結果を統合してスコアリングと最終判定を行うモジュール
"""
from typing import List, Dict, Any

class ScoringEngine:
    def __init__(self):
        # プラグインごとの重み付け（合計が1.0になるように調整）
        self.plugin_weights = {
            'whois-checker': 0.35,   # ドメイン年齢は重要な指標
            'url-pattern': 0.30,     # URL構造も重要
            'dom-analyzer': 0.25,    # フォーム検出も参考になる
            'default': 0.10          # その他のプラグイン
        }
        
        # 深刻度のしきい値
        self.severity_thresholds = {
            'critical': 80,
            'high': 60,
            'medium': 35,
            'low': 15,
            'info': 0
        }
        
        # 推奨アクション
        self.action_recommendations = {
            'critical': 'block',      # アクセスをブロック
            'high': 'warn_strong',    # 強い警告を表示
            'medium': 'warn',         # 警告を表示
            'low': 'notify',          # 通知のみ
            'info': 'allow'           # 許可
        }
    
    def calculate_total_score(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        複数のプラグイン結果を統合して総合スコアを算出
        
        Args:
            results (List[Dict]): 各プラグインの解析結果リスト
            
        Returns:
            Dict: 統合された解析結果
        """
        if not results:
            return self._create_safe_result()
        
        # 重み付けスコアの計算
        weighted_score = 0
        total_weight = 0
        
        for result in results:
            plugin_id = result.get('pluginId', 'unknown')
            score = result.get('score', 0)
            weight = self.plugin_weights.get(plugin_id, self.plugin_weights['default'])
            
            weighted_score += score * weight
            total_weight += weight
        
        # 正規化（重みの合計で割る）
        if total_weight > 0:
            final_score = weighted_score / total_weight
        else:
            final_score = 0
        
        # ボーナス/ペナルティの適用
        final_score = self._apply_score_adjustments(final_score, results)
        
        # 0-100の範囲に収める
        final_score = max(0, min(100, final_score))
        
        # 深刻度を判定
        severity = self._determine_severity(final_score)
        
        # 推奨アクションを決定
        action = self.action_recommendations.get(severity, 'allow')
        
        # ビジュアルエフェクトを決定
        visual_effect = self._determine_visual_effect(severity, final_score)
        
        # 警告メッセージを生成
        warnings = self._generate_warnings(results, severity)
        
        # ユーザー向けの総合メッセージ
        summary_message = self._generate_summary_message(severity, final_score, results)
        
        return {
            'status': 'success',
            'analysis': {
                'url': results[0].get('metadata', {}).get('url', 'unknown'),
                'totalScore': round(final_score, 2),
                'severity': severity,
                'results': results,
                'recommendation': {
                    'action': action,
                    'message': summary_message
                },
                'visualEffect': visual_effect,
                'warnings': warnings,
                'timestamp': self._get_timestamp()
            }
        }
    
    def _apply_score_adjustments(self, base_score: float, results: List[Dict]) -> float:
        """
        特定の条件に基づいてスコアを調整
        """
        adjusted_score = base_score
        
        # 複数の高リスク要因が重なる場合はスコアを増加
        high_severity_count = sum(1 for r in results if r.get('severity') == 'high')
        if high_severity_count >= 2:
            adjusted_score += 15  # ボーナス
        
        # 信頼できるドメインの場合は大幅減点
        for result in results:
            if result.get('metadata', {}).get('trustedDomain'):
                adjusted_score -= 30
        
        # 新しいドメイン + フィッシングキーワードの組み合わせは危険
        has_new_domain = any(
            r.get('pluginId') == 'whois-checker' and 
            r.get('metadata', {}).get('domainAge', 999) < 30
            for r in results
        )
        has_phishing_keywords = any(
            r.get('pluginId') == 'url-pattern' and 
            r.get('metadata', {}).get('phishingKeywords')
            for r in results
        )
        if has_new_domain and has_phishing_keywords:
            adjusted_score += 20  # 危険な組み合わせ
        
        return adjusted_score
    
    def _determine_severity(self, score: float) -> str:
        """スコアから深刻度を判定"""
        for severity, threshold in sorted(
            self.severity_thresholds.items(), 
            key=lambda x: x[1], 
            reverse=True
        ):
            if score >= threshold:
                return severity
        return 'info'
    
    def _determine_visual_effect(self, severity: str, score: float) -> str:
        """表示するビジュアルエフェクトを決定"""
        effect_map = {
            'critical': 'aurora-red',      # 赤いオーロラ
            'high': 'aurora-gold',         # 黄金のオーロラ
            'medium': 'aurora-yellow',     # 黄色のオーロラ
            'low': 'aurora-blue',          # 青いオーロラ
            'info': 'none'                 # エフェクトなし
        }
        return effect_map.get(severity, 'none')
    
    def _generate_warnings(self, results: List[Dict], severity: str) -> List[Dict]:
        """
        ユーザーに表示する警告メッセージのリストを生成
        """
        warnings = []
        
        # 深刻度の高い順にソート
        severity_order = {'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        sorted_results = sorted(
            results,
            key=lambda x: severity_order.get(x.get('severity', 'info'), 0),
            reverse=True
        )
        
        # 各プラグインの理由を警告として追加
        for result in sorted_results:
            plugin_id = result.get('pluginId', 'unknown')
            plugin_severity = result.get('severity', 'info')
            reasons = result.get('reasons', [])
            
            # アイコンを決定
            icon = self._get_icon_for_plugin(plugin_id, plugin_severity)
            
            for reason in reasons:
                warnings.append({
                    'icon': icon,
                    'title': self._get_plugin_display_name(plugin_id),
                    'description': reason,
                    'source': plugin_id,
                    'severity': plugin_severity
                })
        
        return warnings
    
    def _generate_summary_message(self, severity: str, score: float, results: List[Dict]) -> str:
        """総合的な判定メッセージを生成"""
        messages = {
            'critical': 'このサイトは非常に危険です。アクセスを中止することを強く推奨します。',
            'high': 'このサイトはフィッシング詐欺やマルウェアの可能性が高いです。十分に注意してください。',
            'medium': 'このサイトには疑わしい要素が含まれています。個人情報の入力は避けてください。',
            'low': 'このサイトには若干の懸念事項があります。慎重に利用してください。',
            'info': 'このサイトは比較的安全と判断されます。'
        }
        
        base_message = messages.get(severity, 'サイトの安全性を評価できませんでした。')
        
        # 特定の条件で追加メッセージ
        additional_notes = []
        
        # 新規ドメインの警告
        for result in results:
            if result.get('pluginId') == 'whois-checker':
                domain_age = result.get('metadata', {}).get('domainAge')
                if domain_age and domain_age < 7:
                    additional_notes.append('ドメインが非常に新しいため、特に注意が必要です。')
        
        # ログインフォームの警告
        for result in results:
            if result.get('pluginId') == 'dom-analyzer':
                if any('ログイン' in r or 'パスワード' in r for r in result.get('reasons', [])):
                    additional_notes.append('パスワードやクレジットカード情報を入力しないでください。')
        
        if additional_notes:
            base_message += ' ' + ' '.join(additional_notes)
        
        return base_message
    
    def _get_icon_for_plugin(self, plugin_id: str, severity: str) -> str:
        """プラグインと深刻度に応じたアイコンを返す"""
        icons = {
            'whois-checker': {
                'high': '🚨', 'medium': '⚠️', 'low': 'ℹ️', 'info': '✓'
            },
            'url-pattern': {
                'high': '🔴', 'medium': '🟡', 'low': '🔵', 'info': '✓'
            },
            'dom-analyzer': {
                'high': '🔑', 'medium': '🔍', 'low': 'ℹ️', 'info': '✓'
            }
        }
        return icons.get(plugin_id, {}).get(severity, '⚠️')
    
    def _get_plugin_display_name(self, plugin_id: str) -> str:
        """プラグインIDから表示名を取得"""
        names = {
            'whois-checker': 'ドメイン情報',
            'url-pattern': 'URL構造',
            'dom-analyzer': 'ページ要素'
        }
        return names.get(plugin_id, plugin_id)
    
    def _create_safe_result(self) -> Dict:
        """解析結果がない場合の安全な結果を返す"""
        return {
            'status': 'success',
            'analysis': {
                'totalScore': 0,
                'severity': 'info',
                'results': [],
                'recommendation': {
                    'action': 'allow',
                    'message': '特に問題は検出されませんでした。'
                },
                'visualEffect': 'none',
                'warnings': [],
                'timestamp': self._get_timestamp()
            }
        }
    
    def _get_timestamp(self) -> str:
        """現在時刻のタイムスタンプを取得"""
        from datetime import datetime
        return datetime.now().isoformat()