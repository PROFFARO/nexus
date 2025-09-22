#!/usr/bin/env python3
"""
SMB Honeypot Report Generation Script
Standalone script to generate security reports from SMB honeypot data
"""

import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from report_generator import SMBHoneypotReportGenerator
    
    def main():
        """Generate SMB honeypot security report"""
        import argparse
        
        parser = argparse.ArgumentParser(description='Generate SMB honeypot security report')
        parser.add_argument('--sessions-dir', default='sessions', help='Sessions directory path')
        parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
        parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', help='Report format')
        
        args = parser.parse_args()
        
        print(f"Generating SMB security report...")
        print(f"Sessions directory: {args.sessions_dir}")
        print(f"Output directory: {args.output_dir}")
        print(f"Format: {args.format}")
        
        try:
            generator = SMBHoneypotReportGenerator(args.sessions_dir)
            report_files = generator.generate_comprehensive_report(args.output_dir, args.format)
            
            if "error" in report_files:
                print(f"❌ Error: {report_files['error']}")
                return 1
            
            print("\n🛡️ SMB Security Report Generated Successfully!")
            print("=" * 50)
            
            if args.format in ['json', 'both'] and 'json' in report_files:
                print(f"📊 Enhanced JSON Report: {report_files['json']}")
                
            if args.format in ['html', 'both'] and 'html' in report_files:
                print(f"🌐 Modern HTML Report: {report_files['html']}")
                
            if 'visualizations' in report_files:
                print(f"📈 Professional Visualizations:")
                for viz_type, viz_path in report_files['visualizations'].items():
                    if viz_path:
                        print(f"   • {viz_type.replace('_', ' ').title()}: {viz_path}")
                        
            print(f"\n📁 Reports saved to: {args.output_dir}")
            print(f"🔍 Sessions analyzed: {len(generator.sessions_data)}")
            print(f"⚡ Powered by: NEXUS AI Enhanced Analysis Engine")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            print("\n🔧 Debug Information:")
            traceback.print_exc()
            return 1
            
        return 0

    if __name__ == '__main__':
        sys.exit(main())
        
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure all required dependencies are installed")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)