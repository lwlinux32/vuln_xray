"""Example Usage and Integration Examples for VulnX-Ray.

Demonstrates various ways to use the VulnX-Ray scanner in different scenarios.
"""

from vuln_xray import VulnXRayScanner, ExploitSuggestionEngine
from vuln_xray.scanner import ReportGenerator
import sys


def example_basic_scan():
    """Example 1: Basic vulnerability scan."""
    print("="*50)
    print("Example 1: Basic Scan")
    print("="*50)

    scanner = VulnXRayScanner(
        target="https://httpbin.org/get",
        verbose=True,
        output_dir="./reports"
    )

    result = scanner.start(concurrency=5)
    print(f"\nScan complete. Found {result.stats['vulnerabilities_found']} issues.")
    print(f"Duration: {result.scan_duration} seconds")
    scanner.shutdown()


def example_with_exploit_suggestions():
    """Example 2: Scan with exploit suggestion engine."""
    print("\n" + "="*50)
    print("Example 2: With Exploit Suggestions")
    print("="*50)

    scanner = VulnXRayScanner(
        target="https://httpbin.org/post",
        verbose=True,
        ci_mode=False  # Set to True for automated environments
    )

    result = scanner.start()

    # Generate exploit suggestions
    engine = ExploitSuggestionEngine()

    print("\nGenerating exploit suggestions...")
    for finding in result.findings:
        suggestions = engine.generate_exploit_suggestion(
            vuln_type=finding.vulnerability.type.value,
            target=finding.vulnerability.target,
            parameter=finding.vulnerability.parameter,
            payload=finding.vulnerability.payload
        )
        print(f"\n--- {finding.vulnerability.type.value} ---")
        print(f"Target: {suggestions['target']}")
        print(f"Complexity Score: {suggestions['complexity_score']}")
        print(f"Recommended Tools: {', '.join(suggestions['tools'][:3])}")
        print(f"Risk Impact: {suggestions['risk_assessment']['impact']}")
        print(f"POC Code:\n{suggestions['poc_snippet'][:300]}")


def example_ci_cdr_integration():
    """Example 3: CI/CD Integration mode."""
    print("\n" + "="*50)
    print("Example 3: CI/CD Integration")
    print("="*50)

    # Non-interactive mode for automation
    scanner = VulnXRayScanner(
        target="https://httpbin.org/get",
        ci_mode=True,
        verbose=True,
        output_dir="./ci-reports"
    )

    result = scanner.start()

    # Generate reports
    report_gen = ReportGenerator(scanner)

    print("\nGenerating reports...")
    json_path = report_gen.save_report(result, format='json')
    md_path = report_gen.save_report(result, format='markdown')

    print(f"JSON Report: {json_path}")
    print(f"Markdown Report: {md_path}")

    # Print summary
    print(f"\nSummary:")
    print(f"  Target: {result.target}")
    print(f"  Findings: {len(result.findings)}")
    print(f"  Duration: {result.scan_duration}s")


def example_async_scan():
    """Example 4: Async scan with rate limiting (optional)."""
    print("\n" + "="*50)
    print("Example 4: Async Scan")
    print("="*50)

    scanner = VulnXRayScanner(
        target="https://httpbin.org/get",
        verbose=False,
        rate_limit=50,  # Requests per second
        timeout=5
    )

    result = scanner.start(concurrency=15)

    print(f"\nAsync scan complete.")
    print(f"Requests made: {result.stats['requests_made']}")


def example_detailed_fingerprinting():
    """Example 5: Detailed reconnaissance and fingerprinting."""
    print("\n" + "="*50)
    print("Example 5: Fingerprinting")
    print("="*50)

    scanner = VulnXRayScanner(
        target="https://httpbin.org/html",
        verbose=True
    )

    result = scanner.start()

    # Access fingerprints collected
    print(f"\nFingerprints collected:")
    if hasattr(result, 'fingerprints'):
        for tech, version in result.fingerprints.items():
            print(f"  {tech}: {version}")


def example_targeted_scan():
    """Example 6: Targeted scan with specific parameters."""
    print("\n" + "="*50)
    print("Example 6: Targeted Scan")
    print("="*50)

    scanner = VulnXRayScanner(
        target="https://httpbin.org/post",
        verbose=False,
        proxy=""  # Can set proxy if needed
    )

    result = scanner.start()
    print(f"\nTargeted scan complete. Findings: {len(result.findings)}")


def example_report_analysis():
    """Example 7: Analyzing generated reports."""
    print("\n" + "="*50)
    print("Example 7: Report Analysis")
    print("="*50)

    scanner = VulnXRayScanner(
        target="https://httpbin.org/get",
        verbose=False
    )

    result = scanner.start()
    report_gen = ReportGenerator(scanner)

    # Generate JSON
    json_report = report_gen.save_report(result, 'json')

    # Load and display report structure
    import json as json_mod
    with open(json_report, 'r') as f:
        report_data = json_mod.load(f)

    print("\nJSON Report Structure:")
    print(f"  Target: {report_data['scan_info']['target']}")
    print(f"  Duration: {report_data['scan_info']['duration']}s")
    print(f"  Findings count: {len(report_data['findings'])}")

    if report_data['findings']:
        first_finding = report_data['findings'][0]
        print(f"\nFirst Finding:")
        print(f"  Type: {first_finding['vulnerability']['type']}")
        print(f"  Target: {first_finding['vulnerability']['target']}")


def main():
    """Run all examples."""
    try:
        example_basic_scan()
        example_with_exploit_suggestions()
        example_ci_cdr_integration()
        example_async_scan()
        example_detailed_fingerprinting()
        example_targeted_scan()
        example_report_analysis()
        print("\n" + "="*50)
        print("All examples completed!")
        print("="*50)
    except Exception as e:
        print(f"\nError in examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
