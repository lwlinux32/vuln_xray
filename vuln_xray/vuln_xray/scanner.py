"""
Main Vulnerability Scanner Module

This module contains the core VulnXRayScanner class that orchestrates
vulnerability detection, exploitation suggestions, and reporting.
"""

import json
import logging
import re
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VulnXRayScanner:
    """Main vulnerability scanner class."""

    def __init__(self, target: str = "", verbose: bool = False, output_dir: str = ".", ci_mode: bool = False):
        self.target = target
        self.verbose = verbose
        self.output_dir = Path(output_dir)
        self.ci_mode = ci_mode
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnX-Ray/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self.stats = {'requests_made': 0, 'vulnerabilities_found': 0, 'errors': []}

    def start(self, concurrency: int = 10) -> Dict[str, Any]:
        """Start the vulnerability scan."""
        print(f"\n{'='*60}")
        print(f"VulnX-Ray v1.0.0 - Web Vulnerability Scanner")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Concurrency: {concurrency}")
        print(f"Mode: {'CI/CD' if self.ci_mode else 'Interactive'}")
        print(f"{'='*60}\n")

        if not self.target:
            print("[ERROR] No target specified")
            return {}

        # Basic reconnaissance
        try:
            response = self.session.get(self.target, timeout=10)
            self.stats['requests_made'] += 1
            print(f"[INFO] Fetched {self.target} (Status: {response.status_code})")

            # Technology detection
            tech = self._detect_tech(response.text)
            for t, v in tech.items():
                print(f"[RECON] Detected: {t} = {v}")

        except Exception as e:
            print(f"[ERROR] Fetch failed: {e}")

        # Run vulnerability checks
        self._check_sql_injection(response)
        self._check_xss(response)
        self._check_rce(response)

        # Generate report
        result = self._generate_report()
        print(f"\n{'='*60}")
        print(f"Scan Complete: Found {result['findings']} issues")
        print(f"{'='*60}")

        return result

    def _detect_tech(self, html: str) -> Dict[str, str]:
        """Detect web technologies."""
        tech = {}
        html_lower = html.lower()

        patterns = {
            'WordPress': r'wp-content|wp-includes',
            'Django': r'django|staticfiles',
            'Flask': r'flask|werkzeug',
            'Nginx': r'nginx',
            'Apache': r'Apache',
            'PHP': r'php://|phpinfo',
        }

        for name, pattern in patterns.items():
            if re.search(pattern, html_lower):
                tech[name] = 'Detected'
        return tech

    def _check_sql_injection(self, response) -> None:
        """Check for SQL injection."""
        text = response.text.lower()
        sqli_indicators = ['mysql', 'oracle', 'postgresql', 'sqlite', 'syntax error', 'union select']

        if any(ind in text for ind in sqli_indicators):
            print(f"[SQLI] Potential SQL Injection indicators found")
            self.stats['vulnerabilities_found'] += 1

    def _check_xss(self, response) -> None:
        """Check for XSS."""
        text = response.text.lower()
        if 'script' in text and 'alert' in text:
            print(f"[XSS] Potential XSS indicators found")
            self.stats['vulnerabilities_found'] += 1

    def _check_rce(self, response) -> None:
        """Check for RCE."""
        text = response.text.lower()
        if '${' in text or 'jndi' in text:
            print(f"[RCE] Potential RCE indicators found")
            self.stats['vulnerabilities_found'] += 1

    def _generate_report(self) -> Dict[str, Any]:
        """Generate scan report and save files."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = self.output_dir / f'scan_{timestamp}.json'
        md_path = self.output_dir / f'scan_{timestamp}.md'

        # Save JSON
        report = {
            'target': self.target,
            'findings': self.stats['vulnerabilities_found'],
            'requests_made': self.stats['requests_made'],
            'errors': self.stats['errors'],
            'timestamp': datetime.now().isoformat()
        }
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Save Markdown
        with open(md_path, 'w') as f:
            f.write(f"# VulnX-Ray Report: {self.target}\n\n")
            f.write(f"- **Findings**: {report['findings']}\n")
            f.write(f"- **Timestamp**: {report['timestamp']}\n")

        print(f"[REPORT] Saved: {json_path}, {md_path}")
        return report


def main():
    """Main CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='VulnX-Ray - Web Vulnerability Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', default='.', help='Output directory')
    parser.add_argument('-c', '--concurrency', type=int, default=10, help='Concurrency')
    parser.add_argument('--ci', action='store_true', help='CI/CD mode')

    args = parser.parse_args()

    scanner = VulnXRayScanner(
        target=args.target,
        verbose=args.verbose,
        output_dir=args.output,
        ci_mode=args.ci
    )

    result = scanner.start(concurrency=args.concurrency)
    print(f"\nJSON Report: scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    print(f"Markdown Report: scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")


if __name__ == '__main__':
    main()
