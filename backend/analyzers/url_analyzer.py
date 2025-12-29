"""
URLの構造的特徴やフィッシングパターンを解析するモジュール
(backend/analyzers/url_analyzer.py)
"""
import re
from urllib.parse import urlparse

class UrlAnalyzer:
    def analyze(self, url):
        score = 0
        reasons = []
        metadata = {
            'suspiciousPatterns': [],
            'phishingKeywords': []
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # 1. プロトコルチェック
            if parsed.scheme != 'https':
                score += 15
                reasons.append('HTTPSではなくHTTPが使用されています')
                metadata['suspiciousPatterns'].append('no-https')

            # 2. IPアドレス直接指定チェック
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, domain):
                score += 60
                reasons.append('IPアドレスが直接指定されています')
                metadata['suspiciousPatterns'].append('ip-address-host')

            # 3. フィッシングキーワード検出
            suspicious_keywords = [
                'login', 'signin', 'verify', 'secure', 'account', 'update', 
                'banking', 'confirm', 'wallet', 'password'
            ]
            found_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]
            
            if found_keywords:
                if score < 50:
                    score += 20 * len(found_keywords)
                    reasons.append(f"不審なキーワード: {', '.join(found_keywords)}")
                    metadata['phishingKeywords'] = found_keywords
                    metadata['suspiciousPatterns'].append('phishing-keywords')

            # 4. サブドメインの深さ
            dots = domain.count('.')
            if dots > 3 and not re.match(ip_pattern, domain):
                score += 10
                reasons.append('サブドメインが深すぎます')
                metadata['suspiciousPatterns'].append('deep-subdomain')

            # 5. 特殊ポート
            if parsed.port and parsed.port not in [80, 443]:
                score += 10
                reasons.append(f'非標準ポート({parsed.port})を使用')
                metadata['suspiciousPatterns'].append('non-standard-port')

            score = min(score, 100)
            
            severity = 'info'
            if score >= 60: severity = 'high'
            elif score >= 30: severity = 'medium'
            elif score > 0: severity = 'low'

            return {
                "pluginId": "url-pattern",
                "score": score,
                "severity": severity,
                "reasons": reasons if reasons else ["問題なし"],
                "metadata": metadata
            }

        except Exception as e:
            return {
                "pluginId": "url-pattern",
                "score": 0,
                "severity": "info",
                "reasons": [f"解析エラー: {str(e)}"],
                "metadata": {}
            }
            
            