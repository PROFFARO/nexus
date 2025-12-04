#!/usr/bin/env python3
"""
Simple script to generate honeypot reports
"""

from pathlib import Path
from report_generator import SSHHoneypotReportGenerator

def main():
    # Initialize report generator
    sessions_path = Path(__file__).parent / "sessions"
    generator = SSHHoneypotReportGenerator(sessions_dir=str(sessions_path))
    
    # Generate comprehensive report
    print("Generating honeypot security report...")
    report_files = generator.generate_comprehensive_report(output_dir="reports")
    
    if "error" in report_files:
        print(f"Error: {report_files['error']}")
        return
    
    print("Report generation completed!")
    print(f"JSON Report: {report_files.get('json', 'Not generated')}")
    print(f"HTML Report: {report_files.get('html', 'Not generated')}")
    print("Visualizations saved in: reports/visualizations/")

if __name__ == "__main__":
    main()