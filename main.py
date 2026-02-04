"""
PDF Malware Analyzer - Main Entry Point
Analyzes PDF files for malicious content and generates security reports
"""

import os
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

from analyzers.metadata_analyzer import MetadataAnalyzer
from analyzers.object_analyzer import ObjectAnalyzer
from analyzers.javascript_analyzer import JavaScriptAnalyzer
from analyzers.ioc_extractor import IOCExtractor
from analyzers.risk_scorer import RiskScorer
from utils.reports_generator import ReportGenerator


class PDFMalwareAnalyzer:
    """Main analyzer class that orchestrates all analysis modules"""

    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        self.results = {
            'filename': os.path.basename(pdf_path),
            'filepath': pdf_path,
            'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'metadata': {},
            'objects': {},
            'javascript': {},
            'iocs': {},
            'risk_score': 0,
            'severity': 'UNKNOWN'
        }

    def analyze(self):
        """Run complete analysis pipeline"""
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}PDF Malware Analysis Toolkit")
        print(f"{Fore.CYAN}{'=' * 60}\n")

        print(f"{Fore.YELLOW}[*] Analyzing: {self.results['filename']}")
        print(f"{Fore.YELLOW}[*] File Path: {self.pdf_path}\n")

        # Step 1: Metadata Analysis
        print(f"{Fore.BLUE}[1/5] Extracting Metadata...")
        metadata_analyzer = MetadataAnalyzer(self.pdf_path)
        self.results['metadata'] = metadata_analyzer.analyze()

        # Step 2: Object Enumeration
        print(f"{Fore.BLUE}[2/5] Enumerating PDF Objects...")
        object_analyzer = ObjectAnalyzer(self.pdf_path)
        self.results['objects'] = object_analyzer.analyze()

        # Step 3: JavaScript Detection
        print(f"{Fore.BLUE}[3/5] Scanning for JavaScript...")
        js_analyzer = JavaScriptAnalyzer(self.pdf_path)
        self.results['javascript'] = js_analyzer.analyze()

        # Step 4: IOC Extraction
        print(f"{Fore.BLUE}[4/5] Extracting Indicators of Compromise...")
        ioc_extractor = IOCExtractor(self.pdf_path)
        self.results['iocs'] = ioc_extractor.analyze()

        # Step 5: Risk Scoring
        print(f"{Fore.BLUE}[5/5] Calculating Risk Score...")
        risk_scorer = RiskScorer(self.results)
        self.results['risk_score'], self.results['severity'] = risk_scorer.calculate()

        # Display Summary
        self._display_summary()

        return self.results

    def _display_summary(self):
        """Display analysis summary"""
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}ANALYSIS SUMMARY")
        print(f"{Fore.CYAN}{'=' * 60}\n")

        # Severity color coding
        severity = self.results['severity']
        if severity == 'CRITICAL':
            color = Fore.RED
        elif severity == 'HIGH':
            color = Fore.MAGENTA
        elif severity == 'MEDIUM':
            color = Fore.YELLOW
        elif severity == 'LOW':
            color = Fore.GREEN
        else:
            color = Fore.WHITE

        print(f"Risk Score: {color}{self.results['risk_score']}/100")
        print(f"Severity: {color}{severity}{Style.RESET_ALL}\n")

        print(f"{Fore.WHITE}Suspicious Objects Found: {self.results['objects'].get('suspicious_count', 0)}")
        print(f"JavaScript Detected: {self.results['javascript'].get('js_found', False)}")
        print(
            f"IOCs Identified: {len(self.results['iocs'].get('urls', [])) + len(self.results['iocs'].get('ips', []))}\n")

    def generate_report(self, output_dir='reports'):
        """Generate detailed analysis report"""
        print(f"{Fore.GREEN}[*] Generating Analysis Report...")

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        report_gen = ReportGenerator(self.results, output_dir)
        report_path = report_gen.generate()

        print(f"{Fore.GREEN}[✓] Report saved: {report_path}\n")
        return report_path


def main():
    """Main execution function"""

    # Check command line arguments
    if len(sys.argv) < 2:
        print(f"\n{Fore.RED}Usage: python main.py <path_to_pdf_file>")
        print(f"{Fore.YELLOW}Example: python main.py samples/suspicious.pdf\n")
        sys.exit(1)

    pdf_path = sys.argv[1]

    # Validate file exists
    if not os.path.exists(pdf_path):
        print(f"\n{Fore.RED}[!] Error: File not found - {pdf_path}\n")
        sys.exit(1)

    # Validate it's a PDF
    if not pdf_path.lower().endswith('.pdf'):
        print(f"\n{Fore.RED}[!] Error: File must be a PDF\n")
        sys.exit(1)

    try:
        # Initialize analyzer
        analyzer = PDFMalwareAnalyzer(pdf_path)

        # Run analysis
        results = analyzer.analyze()

        # Generate report
        analyzer.generate_report()

        print(f"{Fore.GREEN}{'=' * 60}")
        print(f"{Fore.GREEN}Analysis Complete!")
        print(f"{Fore.GREEN}{'=' * 60}\n")

    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during analysis: {str(e)}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()