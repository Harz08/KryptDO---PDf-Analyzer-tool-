"""
IOC Extractor Module
Extracts Indicators of Compromise (URLs, IPs, emails, hashes) from PDF files
"""

import re
from colorama import Fore
import validators


class IOCExtractor:
    """Extracts Indicators of Compromise from PDF files"""

    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        self.urls = []
        self.ips = []
        self.emails = []
        self.domains = []
        self.file_hashes = []

    def analyze(self):
        """Extract all IOCs from PDF"""
        try:
            # Read PDF content
            with open(self.pdf_path, 'rb') as f:
                content = f.read()

            # Convert to string
            try:
                content_str = content.decode('utf-8', errors='ignore')
            except:
                content_str = str(content)

            # Extract different types of IOCs
            self._extract_urls(content_str)
            self._extract_ips(content_str)
            self._extract_emails(content_str)
            self._extract_domains(content_str)
            self._extract_hashes(content_str)

            # Prepare result
            result = {
                'urls': self.urls,
                'ips': self.ips,
                'emails': self.emails,
                'domains': self.domains,
                'file_hashes': self.file_hashes,
                'total_iocs': len(self.urls) + len(self.ips) + len(self.emails) + len(self.domains) + len(
                    self.file_hashes)
            }

            # Display findings
            self._display_findings()

            return result

        except Exception as e:
            print(f"{Fore.RED}    [!] Error extracting IOCs: {str(e)}")
            return {
                'urls': [],
                'ips': [],
                'emails': [],
                'domains': [],
                'file_hashes': [],
                'total_iocs': 0
            }

    def _extract_urls(self, content):
        """Extract URLs from content"""
        try:
            # URL regex pattern
            url_pattern = re.compile(
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                re.IGNORECASE
            )

            matches = url_pattern.findall(content)

            # Clean and validate URLs
            for url in matches:
                url = url.strip()
                # Remove common PDF artifacts
                url = url.rstrip('>)]}')

                # Validate URL
                if validators.url(url):
                    if url not in self.urls:
                        self.urls.append(url)

        except Exception as e:
            print(f"{Fore.RED}    [!] Error extracting URLs: {str(e)}")

    def _extract_ips(self, content):
        """Extract IP addresses from content"""
        try:
            # IPv4 pattern
            ip_pattern = re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            )

            matches = ip_pattern.findall(content)

            for ip in matches:
                # Skip common false positives (like version numbers)
                if ip not in ['0.0.0.0', '127.0.0.1'] and ip not in self.ips:
                    # Skip IPs that look like version numbers (e.g., 1.0.0.0)
                    parts = ip.split('.')
                    if not (parts[0] in ['1', '2'] and parts[3] == '0'):
                        self.ips.append(ip)

        except Exception as e:
            print(f"{Fore.RED}    [!] Error extracting IPs: {str(e)}")

    def _extract_emails(self, content):
        """Extract email addresses from content"""
        try:
            # Email pattern
            email_pattern = re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            )

            matches = email_pattern.findall(content)

            for email in matches:
                if email not in self.emails:
                    self.emails.append(email)

        except Exception as e:
            print(f"{Fore.RED}    [!] Error extracting emails: {str(e)}")

    def _extract_domains(self, content):
        """Extract domain names from content"""
        try:
            # Domain pattern (without http/https)
            domain_pattern = re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            )

            matches = domain_pattern.findall(content)

            for domain in matches:
                # Skip common false positives
                if domain not in self.domains and not domain.startswith('localhost'):
                    # Validate domain
                    if validators.domain(domain):
                        self.domains.append(domain)

        except Exception as e:
            print(f"{Fore.RED}    [!] Error extracting domains: {str(e)}")

    def _extract_hashes(self, content):
        """Extract file hashes (MD5, SHA1, SHA256) from content"""
        try:
            # MD5 pattern (32 hex chars)
            md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')

            # SHA1 pattern (40 hex chars)
            sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')

            # SHA256 pattern (64 hex chars)
            sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')

            # Find all hash matches
            md5_matches = md5_pattern.findall(content)
            sha1_matches = sha1_pattern.findall(content)
            sha256_matches = sha256_pattern.findall(content)

            # Add to results with type
            for hash_val in md5_matches:
                if hash_val not in [h['hash'] for h in self.file_hashes]:
                    self.file_hashes.append({'type': 'MD5', 'hash': hash_val})

            for hash_val in sha1_matches:
                if hash_val not in [h['hash'] for h in self.file_hashes]:
                    self.file_hashes.append({'type': 'SHA1', 'hash': hash_val})

            for hash_val in sha256_matches:
                if hash_val not in [h['hash'] for h in self.file_hashes]:
                    self.file_hashes.append({'type': 'SHA256', 'hash': hash_val})

        except Exception as e:
            print(f"{Fore.RED}    [!] Error extracting hashes: {str(e)}")

    def _display_findings(self):
        """Display IOC extraction findings"""
        total = len(self.urls) + len(self.ips) + len(self.emails) + len(self.domains) + len(self.file_hashes)

        if total > 0:
            print(f"{Fore.YELLOW}    [!] IOCs found: {total}")

            if self.urls:
                print(f"{Fore.RED}        URLs: {len(self.urls)}")
                for url in self.urls[:3]:  # Show first 3
                    print(f"{Fore.RED}          - {url}")

            if self.ips:
                print(f"{Fore.YELLOW}        IPs: {len(self.ips)}")
                for ip in self.ips[:3]:
                    print(f"{Fore.YELLOW}          - {ip}")

            if self.emails:
                print(f"{Fore.WHITE}        Emails: {len(self.emails)}")

            if self.domains:
                print(f"{Fore.WHITE}        Domains: {len(self.domains)}")

            if self.file_hashes:
                print(f"{Fore.WHITE}        Hashes: {len(self.file_hashes)}")
        else:
            print(f"{Fore.GREEN}    [✓] No IOCs detected")