"""
WHOIS情報を取得してドメインの年齢やレジストラ情報を解析するモジュール
"""
import whois
from datetime import datetime, timezone
import socket

class WhoisAnalyzer:
    def __init__(self):
        self.cache = {}  # 同一ドメインの重複クエリを防ぐキャッシュ
    
    def analyze(self, url):
        """
        URLからドメイン情報を取得し、リスクスコアを算出
        
        Args:
            url (str): 解析対象のURL
            
        Returns:
            dict: 解析結果（スコア、理由、メタデータ）
        """
        try:
            domain = self._extract_domain(url)
            
            # キャッシュチェック
            if domain in self.cache:
                return self.cache[domain]
            
            # WHOIS情報取得
            whois_info = whois.whois(domain)
            
            # 解析実行
            result = self._evaluate_whois(whois_info, domain)
            
            # キャッシュに保存
            self.cache[domain] = result
            return result
            
        except Exception as e:
            return {
                'pluginId': 'whois-checker',
                'score': 0,
                'severity': 'info',
                'reasons': [f'WHOIS情報の取得に失敗しました: {str(e)}'],
                'metadata': {'error': str(e)}
            }
    
    def _extract_domain(self, url):
        """URLからドメイン名を抽出"""
        # プロトコルを削除
        domain = url.replace('https://', '').replace('http://', '')
        # パスやクエリパラメータを削除
        domain = domain.split('/')[0].split('?')[0]
        # ポート番号を削除
        domain = domain.split(':')[0]
        return domain
    
    def _evaluate_whois(self, whois_info, domain):
        """WHOIS情報からリスク評価"""
        score = 0
        reasons = []
        metadata = {}
        
        # 1. ドメイン作成日のチェック
        creation_date = self._get_creation_date(whois_info)
        if creation_date:
            age_days = (datetime.now(timezone.utc) - creation_date).days
            metadata['domainAge'] = age_days
            metadata['creationDate'] = creation_date.strftime('%Y-%m-%d')
            
            if age_days < 30:
                score += 40
                reasons.append(f'ドメイン作成日が {age_days} 日前です（{metadata["creationDate"]}）')
            elif age_days < 90:
                score += 25
                reasons.append(f'ドメインが作成されて {age_days} 日しか経っていません')
            elif age_days < 180:
                score += 15
                reasons.append(f'ドメインは比較的新しいです（{age_days}日前）')
        
        # 2. レジストラ情報のチェック
        registrar = whois_info.get('registrar', '')
        if registrar:
            metadata['registrar'] = registrar
            # 悪用されやすい無料レジストラのリスト（例）
            suspicious_registrars = ['freenom', 'free domain', 'duckdns']
            if any(suspect in registrar.lower() for suspect in suspicious_registrars):
                score += 20
                reasons.append(f'無料ドメインサービスが使用されています: {registrar}')
        
        # 3. WHOIS保護のチェック
        if self._is_whois_protected(whois_info):
            score += 10
            reasons.append('WHOIS情報がプライバシー保護されています')
            metadata['whoisProtected'] = True
        
        # 4. ネームサーバーのチェック
        name_servers = whois_info.get('name_servers', [])
        if name_servers:
            metadata['nameServers'] = name_servers if isinstance(name_servers, list) else [name_servers]
            # よく使われるCDNやクラウドサービスのネームサーバー
            known_services = ['cloudflare', 'amazonaws', 'googledomains', 'azure']
            if not any(service in str(name_servers).lower() for service in known_services):
                score += 5
                reasons.append('マイナーなネームサーバーが使用されています')
        
        # 5. 有効期限のチェック
        expiration_date = self._get_expiration_date(whois_info)
        if expiration_date:
            days_until_expiry = (expiration_date - datetime.now(timezone.utc)).days
            metadata['expirationDate'] = expiration_date.strftime('%Y-%m-%d')
            metadata['daysUntilExpiry'] = days_until_expiry
            
            if days_until_expiry < 30:
                score += 15
                reasons.append(f'ドメインの有効期限が近いです（残り{days_until_expiry}日）')
        
        # スコアに基づいて深刻度を判定
        if score >= 50:
            severity = 'high'
        elif score >= 30:
            severity = 'medium'
        elif score > 0:
            severity = 'low'
        else:
            severity = 'info'
        
        return {
            'pluginId': 'whois-checker',
            'score': min(score, 100),  # 最大100点
            'severity': severity,
            'reasons': reasons if reasons else ['ドメイン情報は正常です'],
            'metadata': metadata
        }
    
    def _get_creation_date(self, whois_info):
        """作成日を取得（複数形式に対応）"""
        creation_date = whois_info.get('creation_date')
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            # タイムゾーン情報を追加
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            return creation_date
        return None
    
    def _get_expiration_date(self, whois_info):
        """有効期限を取得"""
        expiration_date = whois_info.get('expiration_date')
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(expiration_date, datetime):
            if expiration_date.tzinfo is None:
                expiration_date = expiration_date.replace(tzinfo=timezone.utc)
            return expiration_date
        return None
    
    def _is_whois_protected(self, whois_info):
        """WHOIS保護が有効かどうかをチェック"""
        # 一般的なプライバシー保護サービスのキーワード
        privacy_keywords = [
            'privacy', 'protected', 'redacted', 'whoisguard',
            'private registration', 'proxy'
        ]
        
        # 登録者情報をチェック
        registrant = str(whois_info.get('registrant', '')).lower()
        org = str(whois_info.get('org', '')).lower()
        
        return any(keyword in registrant or keyword in org for keyword in privacy_keywords)