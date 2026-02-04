"""
Risk Scorer Module
Calculates overall risk score and severity level based on all analysis results
"""

from colorama import Fore
from config.indicators import RISK_WEIGHTS, SEVERITY_THRESHOLDS


class RiskScorer:
    """Calculates risk score based on analysis findings"""

    def __init__(self, analysis_results):
        self.results = analysis_results
        self.risk_score = 0
        self.severity = 'UNKNOWN'
        self.risk_factors = []

    def calculate(self):
        """Calculate overall risk score"""
        try:
            # Score based on metadata analysis
            self._score_metadata()

            # Score based on object analysis
            self._score_objects()

            # Score based on JavaScript analysis
            self._score_javascript()

            # Score based on IOCs
            self._score_iocs()

            # Cap score at 100
            self.risk_score = min(self.risk_score, 100)

            # Determine severity level
            self.severity = self._determine_severity()

            # Display scoring summary
            self._display_summary()

            return self.risk_score, self.severity

        except Exception as e:
            print(f"{Fore.RED}    [!] Error calculating risk score: {str(e)}")
            return 0, 'UNKNOWN'

    def _score_metadata(self):
        """Score based on metadata findings"""
        try:
            metadata = self.results.get('metadata', {})

            # Suspicious metadata flags
            suspicious_count = metadata.get('suspicious_count', 0)
            if suspicious_count > 0:
                score = RISK_WEIGHTS.get('suspicious_metadata', 5) * suspicious_count
                self.risk_score += score
                self.risk_factors.append(f"Suspicious metadata ({suspicious_count} flags): +{score}")

            # Encrypted PDF
            if metadata.get('metadata', {}).get('is_encrypted', False):
                score = 10
                self.risk_score += score
                self.risk_factors.append(f"Encrypted PDF: +{score}")

        except Exception as e:
            print(f"{Fore.RED}    [!] Error scoring metadata: {str(e)}")

    def _score_objects(self):
        """Score based on object analysis"""
        try:
            objects = self.results.get('objects', {})

            # Suspicious keywords found
            keyword_matches = objects.get('keyword_matches', {})
            if keyword_matches:
                # JavaScript-related keywords
                if '/JavaScript' in keyword_matches or '/JS' in keyword_matches:
                    score = RISK_WEIGHTS.get('javascript_found', 20)
                    self.risk_score += score
                    self.risk_factors.append(f"JavaScript keyword detected: +{score}")

                # Auto-action keywords
                high_risk = objects.get('high_risk_actions', [])
                if high_risk:
                    score = RISK_WEIGHTS.get('auto_action', 25)
                    self.risk_score += score
                    self.risk_factors.append(f"Automatic actions detected ({len(high_risk)}): +{score}")

                # Embedded files
                if '/EmbeddedFile' in keyword_matches:
                    score = RISK_WEIGHTS.get('embedded_file', 15)
                    self.risk_score += score
                    self.risk_factors.append(f"Embedded files detected: +{score}")

        except Exception as e:
            print(f"{Fore.RED}    [!] Error scoring objects: {str(e)}")

    def _score_javascript(self):
        """Score based on JavaScript analysis"""
        try:
            javascript = self.results.get('javascript', {})

            # JavaScript found
            if javascript.get('js_found', False):
                js_count = javascript.get('js_count', 0)

                # Base score for JavaScript
                base_score = RISK_WEIGHTS.get('javascript_found', 20)
                self.risk_score += base_score
                self.risk_factors.append(f"JavaScript detected ({js_count} snippets): +{base_score}")

                # Obfuscation detected
                obfuscation = javascript.get('obfuscation_detected', [])
                if obfuscation:
                    score = RISK_WEIGHTS.get('obfuscation', 20)
                    self.risk_score += score
                    self.risk_factors.append(f"Code obfuscation detected ({len(obfuscation)} patterns): +{score}")

                # Suspicious functions
                suspicious_funcs = javascript.get('suspicious_functions', [])
                if suspicious_funcs:
                    score = len(suspicious_funcs) * 5
                    self.risk_score += score
                    self.risk_factors.append(f"Suspicious JS functions ({len(suspicious_funcs)}): +{score}")

        except Exception as e:
            print(f"{Fore.RED}    [!] Error scoring JavaScript: {str(e)}")

    def _score_iocs(self):
        """Score based on IOCs found"""
        try:
            iocs = self.results.get('iocs', {})

            # URLs found
            urls = iocs.get('urls', [])
            if urls:
                score = RISK_WEIGHTS.get('url_found', 10) * min(len(urls), 3)  # Cap at 3 URLs
                self.risk_score += score
                self.risk_factors.append(f"URLs found ({len(urls)}): +{score}")

            # IPs found
            ips = iocs.get('ips', [])
            if ips:
                score = 15 * min(len(ips), 2)  # Cap at 2 IPs
                self.risk_score += score
                self.risk_factors.append(f"IP addresses found ({len(ips)}): +{score}")

            # Suspicious emails
            emails = iocs.get('emails', [])
            if emails:
                score = 5 * len(emails)
                self.risk_score += score
                self.risk_factors.append(f"Email addresses found ({len(emails)}): +{score}")

        except Exception as e:
            print(f"{Fore.RED}    [!] Error scoring IOCs: {str(e)}")

    def _determine_severity(self):
        """Determine severity level based on risk score"""
        for severity, (min_score, max_score) in SEVERITY_THRESHOLDS.items():
            if min_score <= self.risk_score <= max_score:
                return severity

        return 'UNKNOWN'

    def _display_summary(self):
        """Display risk scoring summary"""
        print(f"{Fore.GREEN}    [✓] Risk assessment complete")
        print(f"{Fore.WHITE}        Final Score: {self.risk_score}/100")
        print(f"        Severity: {self.severity}")

        if self.risk_factors:
            print(f"{Fore.YELLOW}        Key risk factors:")
            for factor in self.risk_factors[:5]:  # Show top 5
                print(f"{Fore.YELLOW}          • {factor}")