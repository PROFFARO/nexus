#!/usr/bin/env python3
"""
SMB Honeypot Report Generator
Generates comprehensive security reports from SMB honeypot session data
"""

import json
import os
import sys
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
from collections import defaultdict, Counter
import base64

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

class SMBHoneypotReportGenerator:
    """Generate comprehensive reports from SMB honeypot sessions"""
    
    def __init__(self, sessions_dir: str = "sessions"):
        self.sessions_dir = Path(sessions_dir)
        self.sessions_data = []
        self.attack_stats = defaultdict(int)
        self.vulnerability_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.command_stats = defaultdict(int)
        
        # Load session data
        self._load_sessions()
        
    def _load_sessions(self):
        """Load all session data from the sessions directory"""
        if not self.sessions_dir.exists():
            print(f"Sessions directory {self.sessions_dir} does not exist")
            return
            
        session_files = list(self.sessions_dir.glob("*/session_*.json"))
        
        for session_file in session_files:
            try:
                with open(session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                    self.sessions_data.append(session_data)
                    self._update_stats(session_data)
            except Exception as e:
                print(f"Error loading session file {session_file}: {e}")
                
    def _update_stats(self, session_data: Dict[str, Any]):
        """Update statistics from session data"""
        # Update IP statistics
        client_ip = session_data.get('client_info', {}).get('ip', 'unknown')
        self.ip_stats[client_ip] += 1
        
        # Update attack statistics
        for analysis in session_data.get('attack_analysis', []):
            for attack_type in analysis.get('attack_types', []):
                self.attack_stats[attack_type] += 1
                
        # Update vulnerability statistics
        for vuln in session_data.get('vulnerabilities', []):
            vuln_id = vuln.get('vulnerability_id', 'unknown')
            self.vulnerability_stats[vuln_id] += 1
            
        # Update command statistics
        for command in session_data.get('commands', []):
            cmd = command.get('command', 'unknown')
            self.command_stats[cmd] += 1
            
    def generate_comprehensive_report(self, output_dir: str = "reports") -> Dict[str, str]:
        """Generate comprehensive security report"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate report data
        report_data = self._generate_report_data()
        
        # Generate JSON report
        json_file = output_path / f"smb_security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        # Generate HTML report
        html_file = output_path / f"smb_security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_content = self._generate_html_report(report_data)
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return {
            'json': str(json_file),
            'html': str(html_file)
        }
        
    def _generate_report_data(self) -> Dict[str, Any]:
        """Generate comprehensive report data"""
        total_sessions = len(self.sessions_data)
        
        # Calculate time range
        start_times = []
        end_times = []
        for session in self.sessions_data:
            if session.get('start_time'):
                start_times.append(session['start_time'])
            if session.get('end_time'):
                end_times.append(session['end_time'])
                
        time_range = {
            'start': min(start_times) if start_times else 'unknown',
            'end': max(end_times) if end_times else 'unknown'
        }
        
        # Top attackers
        top_attackers = dict(Counter(self.ip_stats).most_common(10))
        
        # Top attacks
        top_attacks = dict(Counter(self.attack_stats).most_common(10))
        
        # Top vulnerabilities
        top_vulnerabilities = dict(Counter(self.vulnerability_stats).most_common(10))
        
        # Top commands
        top_commands = dict(Counter(self.command_stats).most_common(20))
        
        # Session analysis
        session_analysis = self._analyze_sessions()
        
        # Attack timeline
        attack_timeline = self._generate_attack_timeline()
        
        # Geographic analysis (placeholder)
        geographic_data = self._analyze_geography()
        
        return {
            'report_metadata': {
                'generated_at': datetime.datetime.now().isoformat(),
                'report_type': 'SMB Honeypot Security Analysis',
                'time_range': time_range,
                'total_sessions': total_sessions,
                'sessions_directory': str(self.sessions_dir)
            },
            'executive_summary': {
                'total_sessions': total_sessions,
                'unique_attackers': len(self.ip_stats),
                'total_attacks': sum(self.attack_stats.values()),
                'total_vulnerabilities': sum(self.vulnerability_stats.values()),
                'total_commands': sum(self.command_stats.values()),
                'most_common_attack': max(self.attack_stats.items(), key=lambda x: x[1])[0] if self.attack_stats else 'none',
                'most_targeted_vulnerability': max(self.vulnerability_stats.items(), key=lambda x: x[1])[0] if self.vulnerability_stats else 'none'
            },
            'attack_statistics': {
                'top_attackers': top_attackers,
                'top_attacks': top_attacks,
                'top_vulnerabilities': top_vulnerabilities,
                'top_commands': top_commands,
                'attack_distribution': dict(self.attack_stats),
                'vulnerability_distribution': dict(self.vulnerability_stats)
            },
            'session_analysis': session_analysis,
            'attack_timeline': attack_timeline,
            'geographic_analysis': geographic_data,
            'detailed_sessions': self._get_detailed_sessions(),
            'recommendations': self._generate_recommendations()
        }
        
    def _analyze_sessions(self) -> Dict[str, Any]:
        """Analyze session patterns and behaviors"""
        session_durations = []
        commands_per_session = []
        attacks_per_session = []
        
        for session in self.sessions_data:
            # Calculate session duration
            if session.get('start_time') and session.get('end_time'):
                try:
                    start = datetime.datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                    end = datetime.datetime.fromisoformat(session['end_time'].replace('Z', '+00:00'))
                    duration = (end - start).total_seconds()
                    session_durations.append(duration)
                except:
                    pass
                    
            # Count commands and attacks
            commands_per_session.append(len(session.get('commands', [])))
            attacks_per_session.append(len(session.get('attack_analysis', [])))
            
        return {
            'average_session_duration': sum(session_durations) / len(session_durations) if session_durations else 0,
            'average_commands_per_session': sum(commands_per_session) / len(commands_per_session) if commands_per_session else 0,
            'average_attacks_per_session': sum(attacks_per_session) / len(attacks_per_session) if attacks_per_session else 0,
            'session_duration_distribution': {
                'min': min(session_durations) if session_durations else 0,
                'max': max(session_durations) if session_durations else 0,
                'median': sorted(session_durations)[len(session_durations)//2] if session_durations else 0
            }
        }
        
    def _generate_attack_timeline(self) -> List[Dict[str, Any]]:
        """Generate chronological attack timeline"""
        timeline = []
        
        for session in self.sessions_data:
            session_start = session.get('start_time', '')
            client_ip = session.get('client_info', {}).get('ip', 'unknown')
            
            for command in session.get('commands', []):
                if command.get('attack_analysis', {}).get('attack_types'):
                    timeline.append({
                        'timestamp': command.get('timestamp', session_start),
                        'client_ip': client_ip,
                        'command': command.get('command', ''),
                        'attack_types': command['attack_analysis']['attack_types'],
                        'severity': command['attack_analysis'].get('severity', 'low'),
                        'threat_score': command['attack_analysis'].get('threat_score', 0)
                    })
                    
        # Sort by timestamp
        timeline.sort(key=lambda x: x.get('timestamp', ''))
        return timeline[:100]  # Limit to most recent 100 events
        
    def _analyze_geography(self) -> Dict[str, Any]:
        """Analyze geographic distribution of attacks"""
        # Placeholder for geographic analysis
        # In a real implementation, you would use IP geolocation services
        return {
            'countries': {'Unknown': len(self.ip_stats)},
            'regions': {'Unknown': len(self.ip_stats)},
            'cities': {'Unknown': len(self.ip_stats)}
        }
        
    def _get_detailed_sessions(self) -> List[Dict[str, Any]]:
        """Get detailed information about top sessions"""
        # Sort sessions by number of attacks
        sorted_sessions = sorted(
            self.sessions_data,
            key=lambda x: len(x.get('attack_analysis', [])),
            reverse=True
        )
        
        detailed = []
        for session in sorted_sessions[:10]:  # Top 10 sessions
            detailed.append({
                'session_id': session.get('session_id', 'unknown'),
                'client_ip': session.get('client_info', {}).get('ip', 'unknown'),
                'start_time': session.get('start_time', ''),
                'end_time': session.get('end_time', ''),
                'total_commands': len(session.get('commands', [])),
                'total_attacks': len(session.get('attack_analysis', [])),
                'total_vulnerabilities': len(session.get('vulnerabilities', [])),
                'attack_types': list(set([
                    attack_type 
                    for analysis in session.get('attack_analysis', [])
                    for attack_type in analysis.get('attack_types', [])
                ])),
                'vulnerability_ids': list(set([
                    vuln.get('vulnerability_id', '')
                    for vuln in session.get('vulnerabilities', [])
                ]))
            })
            
        return detailed
        
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if 'lateral_movement' in self.attack_stats:
            recommendations.append("Implement network segmentation to prevent lateral movement attacks")
            
        if 'credential_harvesting' in self.attack_stats:
            recommendations.append("Deploy additional credential protection mechanisms and monitor for credential theft")
            
        if 'vulnerability_exploitation' in self.attack_stats:
            recommendations.append("Prioritize patching of SMB vulnerabilities, especially EternalBlue and SMBGhost")
            
        if 'reconnaissance' in self.attack_stats:
            recommendations.append("Implement SMB share access controls and monitoring to detect reconnaissance")
            
        if len(self.ip_stats) > 10:
            recommendations.append("Consider implementing IP-based access controls for SMB services")
            
        if not recommendations:
            recommendations.append("Continue monitoring SMB traffic for emerging attack patterns")
            
        return recommendations
        
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMB Honeypot Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #2c3e50; border-left: 4px solid #3498db; padding-left: 15px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background-color: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #e74c3c; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .table th, .table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background-color: #3498db; color: white; }
        .table tr:hover { background-color: #f5f5f5; }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #f39c12; font-weight: bold; }
        .severity-medium { color: #f1c40f; }
        .severity-low { color: #27ae60; }
        .recommendations { background-color: #d5f4e6; padding: 15px; border-radius: 5px; border-left: 4px solid #27ae60; }
        .timeline-item { background-color: #f8f9fa; margin: 10px 0; padding: 10px; border-radius: 5px; border-left: 3px solid #3498db; }
        .command-code { background-color: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SMB Honeypot Security Report</h1>
            <p>Generated on {generated_at}</p>
            <p>Analysis Period: {time_range}</p>
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{total_sessions}</div>
                    <div class="stat-label">Total Sessions</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{unique_attackers}</div>
                    <div class="stat-label">Unique Attackers</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_attacks}</div>
                    <div class="stat-label">Attack Attempts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_vulnerabilities}</div>
                    <div class="stat-label">Vulnerabilities Targeted</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🎯 Top Attack Sources</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Sessions</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
                    {top_attackers_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>⚔️ Attack Patterns</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Attack Type</th>
                        <th>Occurrences</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
                    {attack_patterns_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>🔓 Vulnerability Exploitation</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Vulnerability ID</th>
                        <th>Attempts</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {vulnerabilities_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>💻 Most Common Commands</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Command</th>
                        <th>Frequency</th>
                    </tr>
                </thead>
                <tbody>
                    {commands_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>⏰ Recent Attack Timeline</h2>
            <div>
                {timeline_items}
            </div>
        </div>

        <div class="section">
            <h2>🔍 Detailed Session Analysis</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Client IP</th>
                        <th>Start Time</th>
                        <th>Commands</th>
                        <th>Attacks</th>
                        <th>Attack Types</th>
                    </tr>
                </thead>
                <tbody>
                    {detailed_sessions_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>💡 Security Recommendations</h2>
            <div class="recommendations">
                {recommendations_list}
            </div>
        </div>

        <div class="section">
            <p style="text-align: center; color: #7f8c8d; margin-top: 40px;">
                Report generated by NEXUS SMB Honeypot Security Analysis System
            </p>
        </div>
    </div>
</body>
</html>
        """
        
        # Format data for HTML
        exec_summary = report_data['executive_summary']
        attack_stats = report_data['attack_statistics']
        
        # Generate table rows
        top_attackers_rows = ""
        total_attacker_sessions = sum(attack_stats['top_attackers'].values())
        for ip, count in attack_stats['top_attackers'].items():
            percentage = (count / total_attacker_sessions * 100) if total_attacker_sessions > 0 else 0
            top_attackers_rows += f"<tr><td>{ip}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"
            
        attack_patterns_rows = ""
        total_attacks = sum(attack_stats['top_attacks'].values())
        for attack, count in attack_stats['top_attacks'].items():
            percentage = (count / total_attacks * 100) if total_attacks > 0 else 0
            attack_patterns_rows += f"<tr><td>{attack}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"
            
        vulnerabilities_rows = ""
        for vuln, count in attack_stats['top_vulnerabilities'].items():
            severity_class = "severity-critical" if "critical" in vuln.lower() else "severity-high"
            vulnerabilities_rows += f"<tr><td>{vuln}</td><td>{count}</td><td class='{severity_class}'>High</td></tr>"
            
        commands_rows = ""
        for cmd, count in list(attack_stats['top_commands'].items())[:10]:
            commands_rows += f"<tr><td><span class='command-code'>{cmd[:50]}</span></td><td>{count}</td></tr>"
            
        timeline_items = ""
        for item in report_data['attack_timeline'][:10]:
            timeline_items += f"""
            <div class="timeline-item">
                <strong>{item['timestamp'][:19]}</strong> - {item['client_ip']}<br>
                <span class="command-code">{item['command'][:100]}</span><br>
                <small>Attack Types: {', '.join(item['attack_types'])}</small>
            </div>
            """
            
        detailed_sessions_rows = ""
        for session in report_data['detailed_sessions']:
            attack_types_str = ', '.join(session['attack_types'][:3])
            if len(session['attack_types']) > 3:
                attack_types_str += f" (+{len(session['attack_types']) - 3} more)"
            detailed_sessions_rows += f"""
            <tr>
                <td>{session['client_ip']}</td>
                <td>{session['start_time'][:19]}</td>
                <td>{session['total_commands']}</td>
                <td>{session['total_attacks']}</td>
                <td>{attack_types_str}</td>
            </tr>
            """
            
        recommendations_list = ""
        for rec in report_data['recommendations']:
            recommendations_list += f"<p>• {rec}</p>"
            
        # Fill template
        return html_template.format(
            generated_at=report_data['report_metadata']['generated_at'][:19],
            time_range=f"{report_data['report_metadata']['time_range']['start'][:10]} to {report_data['report_metadata']['time_range']['end'][:10]}",
            total_sessions=exec_summary['total_sessions'],
            unique_attackers=exec_summary['unique_attackers'],
            total_attacks=exec_summary['total_attacks'],
            total_vulnerabilities=exec_summary['total_vulnerabilities'],
            top_attackers_rows=top_attackers_rows,
            attack_patterns_rows=attack_patterns_rows,
            vulnerabilities_rows=vulnerabilities_rows,
            commands_rows=commands_rows,
            timeline_items=timeline_items,
            detailed_sessions_rows=detailed_sessions_rows,
            recommendations_list=recommendations_list
        )

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate SMB honeypot security report')
    parser.add_argument('--sessions-dir', default='sessions', help='Sessions directory path')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', help='Report format')
    
    args = parser.parse_args()
    
    try:
        generator = SMBHoneypotReportGenerator(args.sessions_dir)
        report_files = generator.generate_comprehensive_report(args.output_dir)
        
        print("SMB Security Report Generated Successfully!")
        if args.format in ['json', 'both']:
            print(f"JSON Report: {report_files['json']}")
        if args.format in ['html', 'both']:
            print(f"HTML Report: {report_files['html']}")
            
    except Exception as e:
        print(f"Error generating report: {e}")
        return 1
        
    return 0

if __name__ == '__main__':
    sys.exit(main())