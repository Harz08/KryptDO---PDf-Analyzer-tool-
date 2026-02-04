"""
Metadata Analyzer Module
Extracts and analyzes PDF metadata for suspicious indicators
"""

import os
from datetime import datetime
from PyPDF2 import PdfReader
from colorama import Fore


class MetadataAnalyzer:
    """Analyzes PDF metadata for suspicious patterns"""

    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        self.metadata = {}
        self.suspicious_flags = []

    def analyze(self):
        """Extract and analyze PDF metadata"""
        try:
            reader = PdfReader(self.pdf_path)

            # Extract basic metadata
            if reader.metadata:
                self.metadata = {
                    'title': reader.metadata.get('/Title', 'N/A'),
                    'author': reader.metadata.get('/Author', 'N/A'),
                    'subject': reader.metadata.get('/Subject', 'N/A'),
                    'creator': reader.metadata.get('/Creator', 'N/A'),
                    'producer': reader.metadata.get('/Producer', 'N/A'),
                    'creation_date': reader.metadata.get('/CreationDate', 'N/A'),
                    'mod_date': reader.metadata.get('/ModDate', 'N/A'),
                }
            else:
                self.metadata = {
                    'title': 'N/A',
                    'author': 'N/A',
                    'subject': 'N/A',
                    'creator': 'N/A',
                    'producer': 'N/A',
                    'creation_date': 'N/A',
                    'mod_date': 'N/A',
                }

            # Get file statistics
            file_stats = os.stat(self.pdf_path)
            self.metadata['file_size'] = file_stats.st_size
            self.metadata['num_pages'] = len(reader.pages)

            # Check for encryption
            self.metadata['is_encrypted'] = reader.is_encrypted

            # Analyze for suspicious patterns
            self._check_suspicious_metadata()

            # Prepare result
            result = {
                'metadata': self.metadata,
                'suspicious_flags': self.suspicious_flags,
                'suspicious_count': len(self.suspicious_flags)
            }

            # Display findings
            self._display_metadata()

            return result

        except Exception as e:
            print(f"{Fore.RED}    [!] Error analyzing metadata: {str(e)}")
            return {
                'metadata': {},
                'suspicious_flags': [f"Error: {str(e)}"],
                'suspicious_count': 1
            }

    def _check_suspicious_metadata(self):
        """Check metadata for suspicious patterns"""

        # Check for missing author (common in malware)
        if self.metadata['author'] == 'N/A' or not self.metadata['author']:
            self.suspicious_flags.append("Missing author information")

        # Check for generic/suspicious creator names
        suspicious_creators = ['root', 'admin', 'user', 'test', 'hacker']
        author = str(self.metadata['author']).lower()
        if any(susp in author for susp in suspicious_creators):
            self.suspicious_flags.append(f"Suspicious author name: {self.metadata['author']}")

        # Check for date anomalies
        if self._check_date_anomaly():
            self.suspicious_flags.append("Date anomaly detected (creation date after modification date)")

        # Check for unusual file size (very small PDFs with many pages can be suspicious)
        if self.metadata['num_pages'] > 0:
            avg_page_size = self.metadata['file_size'] / self.metadata['num_pages']
            if avg_page_size < 1000:  # Less than 1KB per page
                self.suspicious_flags.append(f"Unusually small file size per page: {avg_page_size:.2f} bytes/page")

        # Check for encryption (can hide malicious content)
        if self.metadata['is_encrypted']:
            self.suspicious_flags.append("PDF is encrypted")

    def _check_date_anomaly(self):
        """Check if creation date is after modification date"""
        try:
            creation = self.metadata.get('creation_date', '')
            modification = self.metadata.get('mod_date', '')

            if creation == 'N/A' or modification == 'N/A':
                return False

            # PDF dates format: D:YYYYMMDDHHmmSS
            if isinstance(creation, str) and isinstance(modification, str):
                if creation.startswith('D:') and modification.startswith('D:'):
                    creation_str = creation[2:16]
                    mod_str = modification[2:16]

                    if creation_str > mod_str:
                        return True

            return False
        except:
            return False

    def _display_metadata(self):
        """Display extracted metadata"""
        print(f"{Fore.GREEN}    [✓] Metadata extracted")
        print(f"{Fore.WHITE}        Pages: {self.metadata.get('num_pages', 'N/A')}")
        print(f"        Size: {self.metadata.get('file_size', 0)} bytes")
        print(f"        Author: {self.metadata.get('author', 'N/A')}")
        print(f"        Encrypted: {self.metadata.get('is_encrypted', False)}")

        if self.suspicious_flags:
            print(f"{Fore.YELLOW}        Suspicious indicators: {len(self.suspicious_flags)}")