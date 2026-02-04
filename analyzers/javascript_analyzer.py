"""
JavaScript Analyzer Module
Detects and analyzes JavaScript embedded in PDF files
"""

import re
from PyPDF2 import PdfReader
from colorama import Fore
from config.indicators import OBFUSCATION_PATTERNS


class JavaScriptAnalyzer:
    """Detects and analyzes JavaScript in PDF files"""

    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        self.js_found = False
        self.js_snippets = []
        self.obfuscation_detected = []
        self.suspicious_functions = []

    def analyze(self):
        """Detect and analyze JavaScript in PDF"""
        try:
            # Method 1: Search for JavaScript keywords in raw content
            self._search_js_keywords()

            # Method 2: Extract JavaScript from PDF objects
            self._extract_js_objects()

            # Method 3: Analyze extracted JavaScript for obfuscation
            if self.js_snippets:
                self._analyze_obfuscation()

            # Prepare result
            result = {
                'js_found': self.js_found,
                'js_count': len(self.js_snippets),
                'js_snippets': self.js_snippets[:5],  # First 5 snippets
                'obfuscation_detected': self.obfuscation_detected,
                'suspicious_functions': self.suspicious_functions,
                'risk_level': self._calculate_js_risk()
            }

            # Display findings
            self._display_findings()

            return result

        except Exception as e:
            print(f"{Fore.RED}    [!] Error analyzing JavaScript: {str(e)}")
            return {
                'js_found': False,
                'js_count': 0,
                'js_snippets': [],
                'obfuscation_detected': [],
                'suspicious_functions': [],
                'risk_level': 0
            }

    def _search_js_keywords(self):
        """Search for JavaScript-related keywords in PDF"""
        try:
            with open(self.pdf_path, 'rb') as f:
                content = f.read()

            # Convert to string
            try:
                content_str = content.decode('utf-8', errors='ignore')
            except:
                content_str = str(content)

            # Check for JavaScript indicators
            js_indicators = ['/JavaScript', '/JS', 'application/javascript']

            for indicator in js_indicators:
                if indicator in content_str:
                    self.js_found = True
                    break

        except Exception as e:
            print(f"{Fore.RED}    [!] Error searching JS keywords: {str(e)}")

    def _extract_js_objects(self):
        """Extract JavaScript code from PDF objects"""
        try:
            with open(self.pdf_path, 'rb') as f:
                content = f.read()

            # Convert to string
            try:
                content_str = content.decode('utf-8', errors='ignore')
            except:
                content_str = str(content)

            # Use regex to find JavaScript blocks
            # Pattern 1: /JS (...) or /JavaScript (...)
            js_pattern1 = re.compile(r'/(?:JS|JavaScript)\s*(?:\(|\[)(.*?)(?:\)|\])', re.DOTALL | re.IGNORECASE)
            matches1 = js_pattern1.findall(content_str)

            # Pattern 2: Look for common JavaScript functions
            js_pattern2 = re.compile(r'(function\s+\w+\s*\(.*?\)\s*{.*?})', re.DOTALL)
            matches2 = js_pattern2.findall(content_str)

            # Combine and clean matches
            all_matches = matches1 + matches2

            for match in all_matches:
                if len(match.strip()) > 10:  # Ignore very short matches
                    snippet = match[:500]  # First 500 chars
                    self.js_snippets.append(snippet)
                    self.js_found = True

        except Exception as e:
            print(f"{Fore.RED}    [!] Error extracting JS: {str(e)}")

    def _analyze_obfuscation(self):
        """Analyze JavaScript for obfuscation patterns"""
        try:
            for snippet in self.js_snippets:
                # Check for obfuscation patterns
                for pattern in OBFUSCATION_PATTERNS:
                    if pattern in snippet:
                        if pattern not in self.obfuscation_detected:
                            self.obfuscation_detected.append(pattern)

                # Check for suspicious functions
                suspicious_funcs = [
                    'eval', 'unescape', 'fromCharCode',
                    'atob', 'btoa', 'exportDataObject'
                ]

                for func in suspicious_funcs:
                    if func in snippet and func not in self.suspicious_functions:
                        self.suspicious_functions.append(func)

        except Exception as e:
            print(f"{Fore.RED}    [!] Error analyzing obfuscation: {str(e)}")

    def _calculate_js_risk(self):
        """Calculate risk level based on JavaScript analysis"""
        risk = 0

        if self.js_found:
            risk += 20

        if self.obfuscation_detected:
            risk += len(self.obfuscation_detected) * 10

        if self.suspicious_functions:
            risk += len(self.suspicious_functions) * 5

        return min(risk, 100)  # Cap at 100

    def _display_findings(self):
        """Display JavaScript analysis findings"""
        if self.js_found:
            print(f"{Fore.RED}    [!] JavaScript detected!")
            print(f"{Fore.YELLOW}        JS snippets found: {len(self.js_snippets)}")

            if self.obfuscation_detected:
                print(f"{Fore.RED}        Obfuscation patterns: {len(self.obfuscation_detected)}")
                for pattern in self.obfuscation_detected[:3]:
                    print(f"{Fore.RED}          - {pattern}")

            if self.suspicious_functions:
                print(f"{Fore.YELLOW}        Suspicious functions: {', '.join(self.suspicious_functions[:5])}")
        else:
            print(f"{Fore.GREEN}    [✓] No JavaScript detected")