
#!/usr/bin/env python3
"""
Simple script to generate HTTP honeypot reports
"""

import argparse
from report_generator import HTTPHoneypotReportGenerator

def main():
    parser = argparse.ArgumentParser(description='Generate HTTP Honeypot Security Reports')
    parser.add_argument('--sessions-dir', default='sessions', help='Directory containing session files')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', help='Report format')
    
    args = parser.parse_args()
    
    # Initialize HTTP report generator
    generator = HTTPHoneypotReportGenerator(sessions_dir=args.sessions_dir)
    
    # Generate comprehensive report
    print("Generating HTTP honeypot security report...")
    print(f"Sessions directory: {args.sessions_dir}")
    print(f"Output directory: {args.output_dir}")
    print(f"Format: {args.format}")
    
    report_files = generator.generate_comprehensive_report(output_dir=args.output_dir, format_type=args.format)
    
    if "error" in report_files:
        print(f"Error: {report_files['error']}")
        return
    
    print("HTTP Report generation completed!")
    if args.format in ['json', 'both']:
        print(f"JSON Report: {report_files.get('json', 'Not generated')}")
    if args.format in ['html', 'both']:
        print(f"HTML Report: {report_files.get('html', 'Not generated')}")

if __name__ == "__main__":
    main()