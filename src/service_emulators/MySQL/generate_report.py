#!/usr/bin/env python3
"""
Simple script to generate MySQL honeypot reports
"""

from report_generator import MySQLHoneypotReportGenerator

def main():
    # Initialize MySQL report generator
    generator = MySQLHoneypotReportGenerator(sessions_dir="sessions")
    
    # Generate comprehensive report
    print("Generating MySQL honeypot security report...")
    report_files = generator.generate_comprehensive_report(output_dir="reports")
    
    if "error" in report_files:
        print(f"Error: {report_files['error']}")
        return
    
    print("MySQL Report generation completed!")
    print(f"JSON Report: {report_files.get('json', 'Not generated')}")
    print(f"HTML Report: {report_files.get('html', 'Not generated')}")
    print("Visualizations saved in: reports/visualizations/")

if __name__ == "__main__":
    main()