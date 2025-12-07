#!/usr/bin/env python3
"""
Enhanced script to generate MySQL honeypot reports with log analysis
"""

import argparse
import os
from pathlib import Path
from report_generator import MySQLHoneypotReportGenerator

def main():
    parser = argparse.ArgumentParser(description='Generate MySQL Honeypot Security Reports')
    parser.add_argument('--sessions-dir', default='sessions', help='Directory containing session files')
    parser.add_argument('--logs-dir', default='logs', help='Directory containing log files')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', help='Report format')
    
    args = parser.parse_args()
    
    # Resolve paths
    sessions_dir = Path(args.sessions_dir).resolve()
    logs_dir = Path(args.logs_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    
    # Check if directories exist
    if not sessions_dir.exists():
        print(f"Warning: Sessions directory '{sessions_dir}' does not exist")
    
    if not logs_dir.exists():
        print(f"Warning: Logs directory '{logs_dir}' does not exist")
    
    # Initialize MySQL report generator with log analysis
    generator = MySQLHoneypotReportGenerator(
        sessions_dir=str(sessions_dir),
        logs_dir=str(logs_dir)
    )
    
    # Generate comprehensive report
    print("🔍 Analyzing MySQL honeypot data...")
    print(f"📁 Sessions directory: {sessions_dir}")
    print(f"📋 Logs directory: {logs_dir}")
    print(f"📊 Output directory: {output_dir}")
    print(f"📄 Format: {args.format}")
    print()
    
    report_files = generator.generate_comprehensive_report(
        output_dir=str(output_dir),
        format_type=args.format
    )
    
    if "error" in report_files:
        print(f"❌ Error: {report_files['error']}")
        return
    
    print("✅ MySQL honeypot security report generation completed!")
    print()
    
    if args.format in ['json', 'both']:
        print(f"📄 JSON Report: {report_files.get('json', 'Not generated')}")
    
    if args.format in ['html', 'both']:
        print(f"🌐 HTML Report: {report_files.get('html', 'Not generated')}")
    
    print()
    print("🎯 Report Features:")
    print("  • Executive summary with key metrics")
    print("  • Attack pattern analysis")
    print("  • Vulnerability assessment")
    print("  • Database operation tracking")
    print("  • High-risk session identification")
    print("  • Security recommendations")
    print("  • Log file integration")
    print("  • Modern responsive UI (HTML)")

if __name__ == "__main__":
    main()