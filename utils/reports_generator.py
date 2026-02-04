"""
Report Generator Module
Generates detailed PDF malware analysis reports in text format
"""

import os
from datetime import datetime
from colorama import Fore


class ReportGenerator:
    """Generates detailed malware analysis reports"""

    def __init__(self, analysis_results, output_dir='reports'):
        self.results = analysis_results
        self.output_dir = output_dir
        self.report_content = []

    def generate(self):
        """Generate the complete analysis report"""
        try:
            # Build report sections
            self._add_header()
            self._add_executive_summary()
            self._add_metadata_section()
            self._add_object_analysis()
            self._add_javascript_analysis()
            self._add_ioc_section()
            self._add_risk_assessment()
            self._add_recommendations()
            self._add_footer()

            # Write report to file
            report_path = self._write_report()

            return report_path

        except Exception as e:
            print(f"{Fore.RED}    [!] Error generating report: {str(e)}")
            return None

    def _add_header(self):
        """Add report header"""
        self.report_content.append("=" * 80)
        self.report_content.append("PDF MALWARE ANALYSIS REPORT")
        self.report_content.append("=" * 80)
        self.report_content.append("")
        self.report_content.append(f"Report Generated: {self.results['analysis_time']}")
        self.report_content.append(f"Analyzed File: {self.results['filename']}")
        self.report_content.append(f"File Path: {self.results['filepath']}")
        self.report_content.append("")

    def _add_executive_summary(self):
        """Add executive summary"""
        self.report_content.append("-" * 80)
        self.report_content.append("EXECUTIVE SUMMARY")
        self.report_content.append("-" * 80)
        self.report_content.append("")

        severity = self.results['severity']
        risk_score = self.results['risk_score']

        self.report_content.append(f"RISK SCORE: {risk_score}/100")
        self.report_content.append(f"SEVERITY LEVEL: {severity}")
        self.report_content.append("")

        # Summary based on severity
        if severity == 'CRITICAL':
            self.report_content.append("VERDICT: This PDF exhibits CRITICAL malicious indicators.")
            self.report_content.append("ACTION REQUIRED: Do not open this file. Immediate quarantine recommended.")
        elif severity == 'HIGH':
            self.report_content.append("VERDICT: This PDF exhibits HIGH risk indicators.")
            self.report_content.append("ACTION REQUIRED: Exercise extreme caution. Further analysis recommended.")
        elif severity == 'MEDIUM':
            self.report_content.append("VERDICT: This PDF exhibits MEDIUM risk indicators.")
            self.report_content.append("ACTION REQUIRED: Review findings before opening.")
        elif severity == 'LOW':
            self.report_content.append("VERDICT: This PDF exhibits LOW risk indicators.")
            self.report_content.append("ACTION: File appears relatively safe but verify source.")
        else:
            self.report_content.append("VERDICT: Risk level could not be determined.")

        self.report_content.append("")

    def _add_metadata_section(self):
        """Add metadata analysis section"""
        self.report_content.append("-" * 80)
        self.report_content.append("1. METADATA ANALYSIS")
        self.report_content.append("-" * 80)
        self.report_content.append("")

        metadata = self.results.get('metadata', {}).get('metadata', {})

        self.report_content.append(f"Title: {metadata.get('title', 'N/A')}")
        self.report_content.append(f"Author: {metadata.get('author', 'N/A')}")
        self.report_content.append(f"Subject: {metadata.get('subject', 'N/A')}")
        self.report_content.append(f"Creator: {metadata.get('creator', 'N/A')}")
        self.report_content.append(f"Producer: {metadata.get('producer', 'N/A')}")
        self.report_content.append(f"Creation Date: {metadata.get('creation_date', 'N/A')}")
        self.report_content.append(f"Modification Date: {metadata.get('mod_date', 'N/A')}")
        self.report_content.append(f"Number of Pages: {metadata.get('num_pages', 'N/A')}")
        self.report_content.append(f"File Size: {metadata.get('file_size', 0)} bytes")
        self.report_content.append(f"Encrypted: {metadata.get('is_encrypted', False)}")
        self.report_content.append("")

        # Suspicious flags
        suspicious_flags = self.results.get('metadata', {}).get('suspicious_flags', [])
        if suspicious_flags:
            self.report_content.append("SUSPICIOUS METADATA FLAGS:")
            for flag in suspicious_flags:
                self.report_content.append(f"  [!] {flag}")
            self.report_content.append("")

    def _add_object_analysis(self):
        """Add object analysis section"""
        self.report_content.append("-" * 80)
        self.report_content.append("2. OBJECT ANALYSIS")
        self.report_content.append("-" * 80)
        self.report_content.append("")

        objects = self.results.get('objects', {})

        self.report_content.append(f"Total Objects: {objects.get('total_objects', 0)}")
        self.report_content.append(f"Suspicious Objects: {objects.get('suspicious_count', 0)}")
        self.report_content.append("")

        # Keyword matches
        keyword_matches = objects.get('keyword_matches', {})
        if keyword_matches:
            self.report_content.append("SUSPICIOUS KEYWORDS DETECTED:")
            for keyword, count in keyword_matches.items():
                self.report_content.append(f"  {keyword}: {count} occurrence(s)")
            self.report_content.append("")

        # High-risk actions
        high_risk = objects.get('high_risk_actions', [])
        if high_risk:
            self.report_content.append("HIGH-RISK AUTOMATIC ACTIONS:")
            for action in high_risk:
                self.report_content.append(f"  [!] {action['action']}: {action['count']} occurrence(s)")
            self.report_content.append("")

    def _add_javascript_analysis(self):
        """Add JavaScript analysis section"""
        self.report_content.append("-" * 80)
        self.report_content.append("3. JAVASCRIPT ANALYSIS")
        self.report_content.append("-" * 80)
        self.report_content.append("")

        javascript = self.results.get('javascript', {})

        if javascript.get('js_found', False):
            self.report_content.append(f"JavaScript Detected: YES")
            self.report_content.append(f"JavaScript Snippets Found: {javascript.get('js_count', 0)}")
            self.report_content.append("")

            # Obfuscation patterns
            obfuscation = javascript.get('obfuscation_detected', [])
            if obfuscation:
                self.report_content.append("OBFUSCATION PATTERNS DETECTED:")
                for pattern in obfuscation:
                    self.report_content.append(f"  [!] {pattern}")
                self.report_content.append("")

            # Suspicious functions
            suspicious_funcs = javascript.get('suspicious_functions', [])
            if suspicious_funcs:
                self.report_content.append("SUSPICIOUS FUNCTIONS:")
                for func in suspicious_funcs:
                    self.report_content.append(f"  [!] {func}")
                self.report_content.append("")

            # JavaScript snippets (first 3)
            js_snippets = javascript.get('js_snippets', [])
            if js_snippets:
                self.report_content.append("SAMPLE JAVASCRIPT CODE:")
                for i, snippet in enumerate(js_snippets[:3], 1):
                    self.report_content.append(f"\n  Snippet {i}:")
                    # Truncate very long snippets
                    if len(snippet) > 200:
                        snippet = snippet[:200] + "... [truncated]"
                    self.report_content.append(f"  {snippet}")
                self.report_content.append("")
        else:
            self.report_content.append("JavaScript Detected: NO")
            self.report_content.append("")

    def _add_ioc_section(self):
        """Add IOC section"""
        self.report_content.append("-" * 80)
        self.report_content.append("4. INDICATORS OF COMPROMISE (IOCs)")
        self.report_content.append("-" * 80)
        self.report_content.append("")

        iocs = self.results.get('iocs', {})
        total_iocs = iocs.get('total_iocs', 0)

        self.report_content.append(f"Total IOCs Found: {total_iocs}")
        self.report_content.append("")

        # URLs
        urls = iocs.get('urls', [])
        if urls:
            self.report_content.append(f"URLs ({len(urls)}):")
            for url in urls:
                self.report_content.append(f"  - {url}")
            self.report_content.append("")

        # IPs
        ips = iocs.get('ips', [])
        if ips:
            self.report_content.append(f"IP Addresses ({len(ips)}):")
            for ip in ips:
                self.report_content.append(f"  - {ip}")
            self.report_content.append("")

        # Emails
        emails = iocs.get('emails', [])
        if emails:
            self.report_content.append(f"Email Addresses ({len(emails)}):")
            for email in emails:
                self.report_content.append(f"  - {email}")
            self.report_content.append("")

        # Domains
        domains = iocs.get('domains', [])
        if domains:
            self.report_content.append(f"Domains ({len(domains)}):")
            for domain in domains[:10]:  # First 10
                self.report_content.append(f"  - {domain}")
            self.report_content.append("")

        # File hashes
        hashes = iocs.get('file_hashes', [])
        if hashes:
            self.report_content.append(f"File Hashes ({len(hashes)}):")
            for hash_info in hashes:
                self.report_content.append(f"  - {hash_info['type']}: {hash_info['hash']}")
            self.report_content.append("")

        if total_iocs == 0:
            self.report_content.append("No IOCs detected.")
            self.report_content.append("")

    def _add_risk_assessment(self):
        """Add risk assessment section"""
        self.report_content.append("-" * 80)
        self.report_content.append("5. RISK ASSESSMENT")
        self.report_content.append("-" * 80)
        self.report_content.append("")

        self.report_content.append(f"Overall Risk Score: {self.results['risk_score']}/100")
        self.report_content.append(f"Severity Classification: {self.results['severity']}")
        self.report_content.append("")

        # Risk breakdown
        self.report_content.append("Risk Score Breakdown:")
        self.report_content.append("  - 0-30: LOW risk")
        self.report_content.append("  - 31-50: MEDIUM risk")
        self.report_content.append("  - 51-75: HIGH risk")
        self.report_content.append("  - 76-100: CRITICAL risk")
        self.report_content.append("")

    def _add_recommendations(self):
        """Add recommendations section"""
        self.report_content.append("-" * 80)
        self.report_content.append("6. RECOMMENDATIONS & MITIGATION")
        self.report_content.append("-" * 80)
        self.report_content.append("")

        severity = self.results['severity']

        if severity in ['CRITICAL', 'HIGH']:
            self.report_content.append("IMMEDIATE ACTIONS:")
            self.report_content.append("  1. DO NOT open this PDF file")
            self.report_content.append("  2. Quarantine the file immediately")
            self.report_content.append("  3. Report to security team")
            self.report_content.append("  4. Scan system for potential compromise")
            self.report_content.append("  5. Block associated URLs/IPs at network level")
            self.report_content.append("")

        self.report_content.append("GENERAL RECOMMENDATIONS:")
        self.report_content.append("  • Enable PDF reader security features")
        self.report_content.append("  • Disable JavaScript execution in PDF readers")
        self.report_content.append("  • Keep PDF software updated")
        self.report_content.append("  • Verify sender before opening email attachments")
        self.report_content.append("  • Use sandboxed environments for suspicious files")
        self.report_content.append("  • Implement email filtering for PDF attachments")
        self.report_content.append("")

    def _add_footer(self):
        """Add report footer"""
        self.report_content.append("=" * 80)
        self.report_content.append("END OF REPORT")
        self.report_content.append("=" * 80)
        self.report_content.append("")
        self.report_content.append("This report was generated by PDF Malware Analyzer")
        self.report_content.append("For questions or concerns, contact your security team")
        self.report_content.append("")

    def _write_report(self):
        """Write report to file"""
        try:
            # Create output directory if it doesn't exist
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)

            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"analysis_report_{timestamp}.txt"
            report_path = os.path.join(self.output_dir, filename)

            # Write report
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.report_content))

            return report_path

        except Exception as e:
            print(f"{Fore.RED}    [!] Error writing report: {str(e)}")
            return None