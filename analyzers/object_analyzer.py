"""
Object Analyzer Module
Enumerates PDF objects and detects suspicious structures
"""

from PyPDF2 import PdfReader
from colorama import Fore
from config.indicators import SUSPICIOUS_KEYWORDS, HIGH_RISK_ACTIONS


class ObjectAnalyzer:
    """Analyzes PDF objects and structure for malicious patterns"""

    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        self.total_objects = 0
        self.suspicious_objects = []
        self.keyword_matches = {}

    def analyze(self):
        """Enumerate and analyze PDF objects"""
        try:
            reader = PdfReader(self.pdf_path)

            # Count total objects
            if hasattr(reader, 'trailer') and '/Size' in reader.trailer:
                self.total_objects = reader.trailer['/Size']

            # Scan for suspicious keywords in entire PDF
            self._scan_for_keywords()

            # Analyze page objects
            self._analyze_pages(reader)

            # Prepare result
            result = {
                'total_objects': self.total_objects,
                'suspicious_objects': self.suspicious_objects,
                'suspicious_count': len(self.suspicious_objects),
                'keyword_matches': self.keyword_matches,
                'high_risk_actions': self._get_high_risk_actions()
            }

            # Display findings
            self._display_findings()

            return result

        except Exception as e:
            print(f"{Fore.RED}    [!] Error analyzing objects: {str(e)}")
            return {
                'total_objects': 0,
                'suspicious_objects': [],
                'suspicious_count': 0,
                'keyword_matches': {},
                'high_risk_actions': []
            }

    def _scan_for_keywords(self):
        """Scan PDF content for suspicious keywords"""
        try:
            # Read raw PDF content
            with open(self.pdf_path, 'rb') as f:
                pdf_content = f.read()

            # Convert to string for keyword matching
            try:
                content_str = pdf_content.decode('utf-8', errors='ignore')
            except:
                content_str = str(pdf_content)

            # Search for each suspicious keyword
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in content_str:
                    count = content_str.count(keyword)
                    self.keyword_matches[keyword] = count

                    # Log as suspicious object
                    self.suspicious_objects.append({
                        'type': 'keyword',
                        'keyword': keyword,
                        'count': count,
                        'description': f"Found suspicious keyword: {keyword} ({count} times)"
                    })

        except Exception as e:
            print(f"{Fore.RED}    [!] Error scanning keywords: {str(e)}")

    def _analyze_pages(self, reader):
        """Analyze individual page objects"""
        try:
            for page_num, page in enumerate(reader.pages):
                # Check for annotations (can contain JavaScript)
                if '/Annots' in page:
                    self.suspicious_objects.append({
                        'type': 'annotation',
                        'page': page_num + 1,
                        'description': f"Page {page_num + 1} contains annotations"
                    })

                # Check for actions
                if '/AA' in page or '/OpenAction' in page:
                    self.suspicious_objects.append({
                        'type': 'auto_action',
                        'page': page_num + 1,
                        'description': f"Page {page_num + 1} has automatic actions"
                    })

        except Exception as e:
            print(f"{Fore.RED}    [!] Error analyzing pages: {str(e)}")

    def _get_high_risk_actions(self):
        """Identify high-risk automatic actions"""
        high_risk = []

        for keyword in HIGH_RISK_ACTIONS:
            if keyword in self.keyword_matches:
                high_risk.append({
                    'action': keyword,
                    'count': self.keyword_matches[keyword]
                })

        return high_risk

    def _display_findings(self):
        """Display object analysis findings"""
        print(f"{Fore.GREEN}    [✓] Objects analyzed")
        print(f"{Fore.WHITE}        Total objects: {self.total_objects}")
        print(f"        Suspicious objects: {len(self.suspicious_objects)}")

        if self.keyword_matches:
            print(f"{Fore.YELLOW}        Keywords found: {len(self.keyword_matches)}")
            for keyword, count in list(self.keyword_matches.items())[:3]:  # Show first 3
                print(f"{Fore.YELLOW}          - {keyword}: {count} occurrence(s)")