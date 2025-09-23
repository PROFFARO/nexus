#!/usr/bin/env python3
"""
Simple script to generate FTP honeypot reports
"""

from report_generator import FTPHoneypotReportGenerator

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate FTP honeypot security report')
    parser.add_argument('--sessions-dir', default='sessions', help='Sessions directory path')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', help='Report format')
    
    args = parser.parse_args()
    
    # Initialize FTP report generator
    generator = FTPHoneypotReportGenerator(sessions_dir=args.sessions_dir)
    
    # Generate comprehensive report
    print("Generating FTP honeypot security report...")
    report_files = generator.generate_comprehensive_report(output_dir=args.output_dir, format_type=args.format)
    
    if "error" in report_files:
        print(f"Error: {report_files['error']}")
        return
    
    print("FTP Report generation completed!")
    if args.format in ['json', 'both'] and 'json' in report_files:
        print(f"JSON Report: {report_files['json']}")
    if args.format in ['html', 'both'] and 'html' in report_files:
        print(f"HTML Report: {report_files['html']}")
    if args.format in ['both']:
        print("Visualizations saved in: reports/visualizations/")

if __name__ == "__main__":
    main()