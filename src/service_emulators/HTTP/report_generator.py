#!/usr/bin/env python3

"""
HTTP Honeypot Report Generator
Generates comprehensive security reports from HTTP honeypot session data
"""

import json
import os
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from collections import defaultdict, Counter

class HTTPHoneypotReportGenerator:
    """Generate comprehensive security reports from HTTP honeypot data"""
    
    def __init__(self, sessions_dir: str = "sessions"):
        self.sessions_dir = Path(sessions_dir)
        self.report_data = {
            'summary': {},
            'sessions': [],
            'attacks': [],
            'vulnerabilities': [],
            'files': [],
            'statistics': {}
        }
        
    def load_session_data(self) -> bool:
        """Load all session data from JSON files"""
        if not self.sessions_dir.exists():
            return False
            
        session_files = list(self.sessions_dir.glob("*/session_*.json"))
        if not session_files:
            return False
            
        for session_file in session_files:
            try:
                with open(session_file, 'r') as f:
                    session_data = json.load(f)
                    self.report_data['sessions'].append(session_data)
                    
                    # Extract attacks
                    for analysis in session_data.get('attack_analysis', []):
                        if analysis.get('attack_types'):
                            self.report_data['attacks'].append(analysis)
                    
                    # Extract vulnerabilities
                    self.report_data['vulnerabilities'].extend(
                        session_data.get('vulnerabilities', [])
                    )
                    
                    # Extract file operations
                    self.report_data['files'].extend(
                        session_data.get('files_uploaded', [])
                    )
                    
            except Exception as e:
                print(f"Error loading session {session_file}: {e}")
                continue
                
        return len(self.report_data['sessions']) > 0
    
    def generate_statistics(self):
        """Generate comprehensive statistics"""
        sessions = self.report_data['sessions']
        attacks = self.report_data['attacks']
        vulnerabilities = self.report_data['vulnerabilities']
        
        # Basic statistics
        self.report_data['statistics'] = {
            'total_sessions': len(sessions),
            'total_attacks': len(attacks),
            'total_vulnerabilities': len(vulnerabilities),
            'total_files_uploaded': len(self.report_data['files']),
            'unique_ips': len(set(req.get('src_ip', 'unknown') 
                                for session in sessions 
                                for req in session.get('requests', []))),
            'attack_types': Counter(attack_type 
                                  for attack in attacks 
                                  for attack_type in attack.get('attack_types', [])),
            'vulnerability_types': Counter(vuln.get('vulnerability_id', 'unknown') 
                                         for vuln in vulnerabilities),
            'severity_distribution': Counter(attack.get('severity', 'unknown') 
                                           for attack in attacks),
            'http_methods': Counter(req.get('method', 'unknown')
                                  for session in sessions
                                  for req in session.get('requests', [])),
            'user_agents': Counter(req.get('headers', {}).get('User-Agent', 'unknown')
                                 for session in sessions
                                 for req in session.get('requests', []))
        }
        
        # Time-based analysis
        session_times = []
        for session in sessions:
            try:
                start_time = datetime.datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                session_times.append(start_time)
            except:
                continue
                
        if session_times:
            self.report_data['statistics']['time_range'] = {
                'start': min(session_times).isoformat(),
                'end': max(session_times).isoformat(),
                'duration_days': (max(session_times) - min(session_times)).days
            }
    
    def generate_visualizations(self, output_dir: Path):
        """Generate visualization charts"""
        viz_dir = output_dir / "visualizations"
        viz_dir.mkdir(exist_ok=True)
        
        stats = self.report_data['statistics']
        
        # Set style
        plt.style.use('seaborn-v0_8')
        
        # Attack types distribution
        if stats['attack_types']:
            plt.figure(figsize=(12, 6))
            attack_data = dict(stats['attack_types'].most_common(10))
            plt.bar(attack_data.keys(), attack_data.values())
            plt.title('Top 10 HTTP Attack Types')
            plt.xlabel('Attack Type')
            plt.ylabel('Count')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.savefig(viz_dir / "attack_types.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        # Severity distribution pie chart
        if stats['severity_distribution']:
            plt.figure(figsize=(8, 8))
            severity_data = dict(stats['severity_distribution'])
            colors = {'critical': '#d32f2f', 'high': '#f57c00', 'medium': '#fbc02d', 'low': '#388e3c'}
            plt.pie(severity_data.values(), labels=severity_data.keys(), autopct='%1.1f%%',
                   colors=[colors.get(k, '#757575') for k in severity_data.keys()])
            plt.title('Attack Severity Distribution')
            plt.savefig(viz_dir / "severity_distribution.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        # HTTP methods distribution
        if stats['http_methods']:
            plt.figure(figsize=(10, 6))
            method_data = dict(stats['http_methods'])
            plt.bar(method_data.keys(), method_data.values())
            plt.title('HTTP Methods Distribution')
            plt.xlabel('HTTP Method')
            plt.ylabel('Count')
            plt.tight_layout()
            plt.savefig(viz_dir / "http_methods.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        # Top user agents
        if stats['user_agents']:
            plt.figure(figsize=(14, 8))
            ua_data = dict(stats['user_agents'].most_common(10))
            # Truncate long user agent strings
            ua_labels = [ua[:50] + '...' if len(ua) > 50 else ua for ua in ua_data.keys()]
            plt.barh(ua_labels, list(ua_data.values()))
            plt.title('Top 10 User Agents')
            plt.xlabel('Count')
            plt.tight_layout()
            plt.savefig(viz_dir / "user_agents.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        return viz_dir
    
    def generate_json_report(self, output_dir: Path) -> Path:
        """Generate JSON format report"""
        report_file = output_dir / f"http_security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            'metadata': {
                'generated_at': datetime.datetime.now().isoformat(),
                'report_type': 'HTTP Honeypot Security Analysis',
                'sessions_analyzed': len(self.report_data['sessions']),
                'data_source': str(self.sessions_dir)
            },
            'executive_summary': {
                'total_sessions': self.report_data['statistics']['total_sessions'],
                'total_attacks': self.report_data['statistics']['total_attacks'],
                'unique_attackers': self.report_data['statistics']['unique_ips'],
                'critical_vulnerabilities': sum(1 for v in self.report_data['vulnerabilities'] 
                                              if v.get('severity') == 'critical'),
                'files_uploaded': self.report_data['statistics']['total_files_uploaded']
            },
            'detailed_statistics': self.report_data['statistics'],
            'attack_analysis': {
                'attacks_by_type': dict(self.report_data['statistics']['attack_types']),
                'severity_breakdown': dict(self.report_data['statistics']['severity_distribution']),
                'detailed_attacks': self.report_data['attacks'][:50]  # Limit for readability
            },
            'vulnerability_analysis': {
                'vulnerabilities_by_type': dict(self.report_data['statistics']['vulnerability_types']),
                'detailed_vulnerabilities': self.report_data['vulnerabilities'][:50]
            },
            'session_analysis': {
                'http_methods': dict(self.report_data['statistics']['http_methods']),
                'top_user_agents': dict(self.report_data['statistics']['user_agents'].most_common(20)),
                'sample_sessions': self.report_data['sessions'][:10]
            },
            'file_operations': {
                'total_uploads': len(self.report_data['files']),
                'upload_details': self.report_data['files'][:20]
            }
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
            
        return report_file
    
    def generate_html_report(self, output_dir: Path) -> Path:
        """Generate HTML format report"""
        report_file = output_dir / f"http_security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        stats = self.report_data['statistics']
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>HTTP Honeypot Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .metric {{ display: inline-block; margin: 10px 20px; text-align: center; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #e74c3c; }}
        .metric-label {{ color: #7f8c8d; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
        .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        .severity-high {{ color: #f39c12; font-weight: bold; }}
        .severity-medium {{ color: #f1c40f; font-weight: bold; }}
        .severity-low {{ color: #27ae60; font-weight: bold; }}
        .chart-container {{ text-align: center; margin: 20px 0; }}
        .chart-container img {{ max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🕸️ HTTP Honeypot Security Report</h1>
        <p><strong>Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p><strong>Analysis Period:</strong> {stats.get('time_range', {}).get('start', 'N/A')} to {stats.get('time_range', {}).get('end', 'N/A')}</p>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="metric">
                <div class="metric-value">{stats['total_sessions']}</div>
                <div class="metric-label">Total Sessions</div>
            </div>
            <div class="metric">
                <div class="metric-value">{stats['total_attacks']}</div>
                <div class="metric-label">Attack Attempts</div>
            </div>
            <div class="metric">
                <div class="metric-value">{stats['unique_ips']}</div>
                <div class="metric-label">Unique IPs</div>
            </div>
            <div class="metric">
                <div class="metric-value">{stats['total_vulnerabilities']}</div>
                <div class="metric-label">Vulnerabilities</div>
            </div>
            <div class="metric">
                <div class="metric-value">{stats['total_files_uploaded']}</div>
                <div class="metric-label">Files Uploaded</div>
            </div>
        </div>
        
        <h2>🎯 Attack Analysis</h2>
        <h3>Top Attack Types</h3>
        <table>
            <tr><th>Attack Type</th><th>Count</th><th>Percentage</th></tr>
        """
        
        total_attacks = sum(stats['attack_types'].values()) if stats['attack_types'] else 1
        for attack_type, count in stats['attack_types'].most_common(10):
            percentage = (count / total_attacks) * 100
            html_content += f"<tr><td>{attack_type}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"
        
        html_content += """
        </table>
        
        <h3>Severity Distribution</h3>
        <table>
            <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
        """
        
        total_severity = sum(stats['severity_distribution'].values()) if stats['severity_distribution'] else 1
        for severity, count in stats['severity_distribution'].most_common():
            percentage = (count / total_severity) * 100
            css_class = f"severity-{severity}"
            html_content += f'<tr><td class="{css_class}">{severity.upper()}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>'
        
        html_content += f"""
        </table>
        
        <h2>🌐 HTTP Traffic Analysis</h2>
        <h3>HTTP Methods</h3>
        <table>
            <tr><th>Method</th><th>Count</th><th>Percentage</th></tr>
        """
        
        total_methods = sum(stats['http_methods'].values()) if stats['http_methods'] else 1
        for method, count in stats['http_methods'].most_common():
            percentage = (count / total_methods) * 100
            html_content += f"<tr><td>{method}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"
        
        html_content += """
        </table>
        
        <h3>Top User Agents</h3>
        <table>
            <tr><th>User Agent</th><th>Count</th></tr>
        """
        
        for ua, count in stats['user_agents'].most_common(10):
            ua_display = ua[:100] + '...' if len(ua) > 100 else ua
            html_content += f"<tr><td>{ua_display}</td><td>{count}</td></tr>"
        
        html_content += f"""
        </table>
        
        <h2>🔍 Vulnerability Analysis</h2>
        <table>
            <tr><th>Vulnerability Type</th><th>Count</th><th>Severity</th></tr>
        """
        
        vuln_details = defaultdict(lambda: {'count': 0, 'severity': 'unknown'})
        for vuln in self.report_data['vulnerabilities']:
            vuln_id = vuln.get('vulnerability_id', 'unknown')
            vuln_details[vuln_id]['count'] += 1
            vuln_details[vuln_id]['severity'] = vuln.get('severity', 'unknown')
        
        for vuln_id, details in sorted(vuln_details.items(), key=lambda x: x[1]['count'], reverse=True):
            css_class = f"severity-{details['severity']}"
            html_content += f'<tr><td>{vuln_id}</td><td>{details["count"]}</td><td class="{css_class}">{details["severity"].upper()}</td></tr>'
        
        html_content += """
        </table>
        
        <h2>📈 Visualizations</h2>
        <div class="chart-container">
            <h3>Attack Types Distribution</h3>
            <img src="visualizations/attack_types.png" alt="Attack Types Chart">
        </div>
        <div class="chart-container">
            <h3>Severity Distribution</h3>
            <img src="visualizations/severity_distribution.png" alt="Severity Distribution Chart">
        </div>
        <div class="chart-container">
            <h3>HTTP Methods</h3>
            <img src="visualizations/http_methods.png" alt="HTTP Methods Chart">
        </div>
        <div class="chart-container">
            <h3>Top User Agents</h3>
            <img src="visualizations/user_agents.png" alt="User Agents Chart">
        </div>
        
        <h2>📋 Recommendations</h2>
        <ul>
        """
        
        # Generate recommendations based on data
        recommendations = []
        
        if stats['total_attacks'] > 100:
            recommendations.append("High attack volume detected. Consider implementing rate limiting and IP blocking.")
        
        if any(severity == 'critical' for severity in stats['severity_distribution']):
            recommendations.append("Critical severity attacks detected. Immediate security review recommended.")
        
        if 'sql_injection' in stats['attack_types']:
            recommendations.append("SQL injection attempts detected. Review database security and input validation.")
        
        if 'xss' in stats['attack_types']:
            recommendations.append("XSS attacks detected. Implement proper output encoding and CSP headers.")
        
        if stats['total_files_uploaded'] > 0:
            recommendations.append("File uploads detected. Review uploaded files for malware and implement file type restrictions.")
        
        if not recommendations:
            recommendations.append("No immediate security concerns identified. Continue monitoring.")
        
        for rec in recommendations:
            html_content += f"<li>{rec}</li>"
        
        html_content += """
        </ul>
        
        <hr>
        <p><small>Report generated by NEXUS HTTP Honeypot Security Analysis System</small></p>
    </div>
</body>
</html>
        """
        
        with open(report_file, 'w') as f:
            f.write(html_content)
            
        return report_file
    
    def generate_comprehensive_report(self, output_dir: str = "reports") -> Dict[str, str]:
        """Generate comprehensive security report in multiple formats"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Load session data
        if not self.load_session_data():
            return {"error": "No session data found or failed to load sessions"}
        
        # Generate statistics
        self.generate_statistics()
        
        # Generate visualizations
        try:
            viz_dir = self.generate_visualizations(output_path)
        except Exception as e:
            print(f"Warning: Failed to generate visualizations: {e}")
            viz_dir = None
        
        # Generate reports
        report_files = {}
        
        try:
            json_report = self.generate_json_report(output_path)
            report_files['json'] = str(json_report)
        except Exception as e:
            print(f"Error generating JSON report: {e}")
        
        try:
            html_report = self.generate_html_report(output_path)
            report_files['html'] = str(html_report)
        except Exception as e:
            print(f"Error generating HTML report: {e}")
        
        if viz_dir:
            report_files['visualizations'] = str(viz_dir)
        
        return report_files

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate HTTP honeypot security reports')
    parser.add_argument('--sessions-dir', default='sessions', help='Sessions directory')
    parser.add_argument('--output-dir', default='reports', help='Output directory')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', help='Report format')
    
    args = parser.parse_args()
    
    generator = HTTPHoneypotReportGenerator(args.sessions_dir)
    report_files = generator.generate_comprehensive_report(args.output_dir)
    
    if "error" in report_files:
        print(f"Error: {report_files['error']}")
        exit(1)
    
    print("HTTP Security Report Generated Successfully!")
    for format_type, file_path in report_files.items():
        print(f"{format_type.upper()}: {file_path}")