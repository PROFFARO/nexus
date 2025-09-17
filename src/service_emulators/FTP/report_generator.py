#!/usr/bin/env python3
"""
AI-Enhanced FTP Honeypot Report Generator
Generates comprehensive attack analysis reports with AI insights
"""

import json
import os
import datetime
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from collections import Counter, defaultdict
import numpy as np

class FTPHoneypotReportGenerator:
    """Generate comprehensive reports from FTP honeypot session data with integrated JSON threat intelligence"""
    
    def __init__(self, sessions_dir: str = "sessions"):
        self.sessions_dir = Path(sessions_dir)
        # Load integrated threat intelligence from JSON files
        self.attack_patterns = self._load_attack_patterns()
        self.vulnerability_signatures = self._load_vulnerability_signatures()
        
        self.report_templates = {
            'executive_summary': self._generate_executive_summary,
            'technical_analysis': self._generate_technical_analysis,
            'attack_timeline': self._generate_attack_timeline,
            'threat_intelligence': self._generate_threat_intelligence,
            'forensic_analysis': self._generate_forensic_analysis,
            'recommendations': self._generate_recommendations
        }
        
    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load attack patterns from JSON configuration"""
        try:
            patterns_file = Path(__file__).parent / "attack_patterns.json"
            with open(patterns_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load attack patterns: {e}")
            return {}
            
    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures from JSON configuration"""
        try:
            vuln_file = Path(__file__).parent / "vulnerability_signatures.json"
            with open(vuln_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load vulnerability signatures: {e}")
            return {}
        
    def generate_comprehensive_report(self, output_dir: str = "reports") -> Dict[str, str]:
        """Generate a comprehensive FTP security report"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Collect all session data
        session_data = self._collect_session_data()
        
        if not session_data:
            return {"error": "No FTP session data found"}
        
        # Generate report sections
        report = {
            'metadata': self._generate_metadata(session_data),
            'executive_summary': self._generate_executive_summary(session_data),
            'attack_statistics': self._generate_attack_statistics(session_data),
            'technical_analysis': self._generate_technical_analysis(session_data),
            'attack_timeline': self._generate_attack_timeline(session_data),
            'threat_intelligence': self._generate_threat_intelligence(session_data),
            'forensic_analysis': self._generate_forensic_analysis(session_data),
            'iocs': self._generate_iocs(session_data),
            'recommendations': self._generate_recommendations(session_data),
            'appendix': self._generate_appendix(session_data)
        }
        
        # Save reports in different formats
        report_files = {}
        
        # JSON Report
        json_file = output_path / f"ftp_honeypot_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        report_files['json'] = str(json_file)
        
        # HTML Report
        html_file = output_path / f"ftp_honeypot_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_content = self._generate_html_report(report)
        with open(html_file, 'w') as f:
            f.write(html_content)
        report_files['html'] = str(html_file)
        
        # Generate visualizations
        viz_dir = output_path / "visualizations"
        viz_dir.mkdir(exist_ok=True)
        self._generate_visualizations(session_data, viz_dir)
        
        return report_files
    
    def _collect_session_data(self) -> List[Dict[str, Any]]:
        """Collect data from all FTP session directories"""
        session_data = []
        
        if not self.sessions_dir.exists():
            print(f"Sessions directory {self.sessions_dir} does not exist")
            return session_data
        
        for session_dir in self.sessions_dir.iterdir():
            if session_dir.is_dir():
                session_file = session_dir / "session_summary.json"
                forensic_file = session_dir / "forensic_chain.json"
                
                session_info = {'session_id': session_dir.name}
                
                # Load session summary
                if session_file.exists():
                    try:
                        with open(session_file, 'r') as f:
                            session_info.update(json.load(f))
                    except Exception as e:
                        print(f"Error loading FTP session {session_dir.name}: {e}")
                        continue
                
                # Load forensic data
                if forensic_file.exists():
                    try:
                        with open(forensic_file, 'r') as f:
                            forensic_data = json.load(f)
                            session_info['forensic_data'] = forensic_data
                    except Exception as e:
                        print(f"Error loading forensic data for {session_dir.name}: {e}")
                
                session_data.append(session_info)
        
        print(f"Loaded {len(session_data)} FTP sessions from {self.sessions_dir}")
        return session_data
    
    def _generate_metadata(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate report metadata"""
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'report_version': '1.0',
            'honeypot_type': 'FTP AI-Enhanced Medium Interaction',
            'total_sessions': len(session_data),
            'analysis_period': {
                'start': min(s.get('start_time', '') for s in session_data) if session_data else '',
                'end': max(s.get('end_time', '') for s in session_data) if session_data else ''
            },
            'report_id': hashlib.sha256(f"{datetime.datetime.now().isoformat()}{len(session_data)}".encode()).hexdigest()[:16],
            'threat_intelligence': {
                'attack_patterns_loaded': len(self.attack_patterns),
                'vulnerability_signatures_loaded': len(self.vulnerability_signatures)
            }
        }
    
    def _generate_executive_summary(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate executive summary for FTP honeypot"""
        total_sessions = len(session_data)
        total_commands = sum(len(s.get('commands', [])) for s in session_data)
        total_attacks = sum(len(s.get('attack_analysis', [])) for s in session_data)
        total_vulnerabilities = sum(len(s.get('vulnerabilities', [])) for s in session_data)
        
        # Analyze attack severity
        severity_counts = Counter()
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                severity_counts[attack.get('severity', 'unknown')] += 1
        
        # Top attack types
        attack_types = Counter()
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                for attack_type in attack.get('attack_types', []):
                    attack_types[attack_type] += 1
        
        # Source IPs
        source_ips = Counter()
        for session in session_data:
            forensic_data = session.get('forensic_data', {})
            for event in forensic_data.get('events', []):
                if event.get('event_type') == 'connection_established':
                    src_ip = event.get('data', {}).get('src_ip')
                    if src_ip:
                        source_ips[src_ip] += 1
        
        return {
            'overview': {
                'total_sessions': total_sessions,
                'total_commands_executed': total_commands,
                'total_attack_attempts': total_attacks,
                'total_vulnerability_exploits': total_vulnerabilities,
                'unique_source_ips': len(source_ips),
                'analysis_period_days': self._calculate_analysis_period(session_data)
            },
            'threat_landscape': {
                'severity_distribution': dict(severity_counts),
                'top_attack_types': dict(attack_types.most_common(10)),
                'top_source_ips': dict(source_ips.most_common(10))
            },
            'key_findings': self._generate_key_findings(session_data),
            'risk_assessment': self._assess_risk_level(session_data)
        }
    
    def _generate_attack_statistics(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed FTP attack statistics"""
        stats = {
            'command_analysis': {},
            'attack_patterns': {},
            'temporal_analysis': {},
            'file_operations': {},
            'authentication_analysis': {}
        }
        
        # FTP Command analysis
        all_commands = []
        for session in session_data:
            for cmd in session.get('commands', []):
                all_commands.append(cmd.get('command', ''))
        
        command_counter = Counter(all_commands)
        stats['command_analysis'] = {
            'total_commands': len(all_commands),
            'unique_commands': len(command_counter),
            'most_common_commands': dict(command_counter.most_common(20)),
            'command_categories': self._categorize_ftp_commands(all_commands)
        }
        
        # Attack pattern analysis
        attack_patterns = defaultdict(int)
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                for pattern in attack.get('attack_types', []):
                    attack_patterns[pattern] += 1
        
        stats['attack_patterns'] = {
            'total_patterns': sum(attack_patterns.values()),
            'unique_patterns': len(attack_patterns),
            'pattern_distribution': dict(attack_patterns)
        }
        
        # File operations
        file_ops = {
            'downloads': 0,
            'uploads': 0,
            'directory_listings': 0
        }
        
        for session in session_data:
            file_ops['downloads'] += len(session.get('files_downloaded', []))
            file_ops['uploads'] += len(session.get('files_uploaded', []))
            # Count LIST/NLST commands
            for cmd in session.get('commands', []):
                if cmd.get('command', '').upper().startswith(('LIST', 'NLST')):
                    file_ops['directory_listings'] += 1
        
        stats['file_operations'] = file_ops
        
        # Authentication analysis
        auth_attempts = {'successful': 0, 'failed': 0, 'anonymous': 0}
        for session in session_data:
            for cmd in session.get('commands', []):
                command = cmd.get('command', '').upper()
                if command.startswith('USER'):
                    if 'anonymous' in command.lower():
                        auth_attempts['anonymous'] += 1
                # This would need to be enhanced based on actual session data structure
        
        stats['authentication_analysis'] = auth_attempts
        
        return stats
    
    def _generate_technical_analysis(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate technical analysis section for FTP"""
        analysis = {
            'ftp_attack_vectors': self._analyze_ftp_attack_vectors(session_data),
            'directory_traversal': self._analyze_directory_traversal(session_data),
            'bounce_attacks': self._analyze_bounce_attacks(session_data),
            'brute_force_attempts': self._analyze_brute_force(session_data),
            'malicious_uploads': self._analyze_malicious_uploads(session_data)
        }
        
        return analysis
    
    def _generate_attack_timeline(self, session_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate chronological FTP attack timeline"""
        timeline = []
        
        for session in session_data:
            session_id = session.get('session_id', 'unknown')
            start_time = session.get('start_time', '')
            
            # Add session start
            timeline.append({
                'timestamp': start_time,
                'event_type': 'ftp_session_start',
                'session_id': session_id,
                'description': f'New FTP session initiated',
                'severity': 'info'
            })
            
            # Add FTP commands and attacks
            for cmd in session.get('commands', []):
                timeline.append({
                    'timestamp': cmd.get('timestamp', ''),
                    'event_type': 'ftp_command_execution',
                    'session_id': session_id,
                    'command': cmd.get('command', ''),
                    'description': f'FTP command executed: {cmd.get("command", "")[:50]}...',
                    'severity': 'low'
                })
            
            # Add attack events
            for attack in session.get('attack_analysis', []):
                if attack.get('attack_types'):
                    timeline.append({
                        'timestamp': attack.get('timestamp', ''),
                        'event_type': 'ftp_attack_detected',
                        'session_id': session_id,
                        'attack_types': attack.get('attack_types', []),
                        'description': f'FTP attack detected: {", ".join(attack.get("attack_types", []))}',
                        'severity': attack.get('severity', 'medium')
                    })
            
            # Add vulnerability exploits
            for vuln in session.get('vulnerabilities', []):
                timeline.append({
                    'timestamp': vuln.get('timestamp', ''),
                    'event_type': 'ftp_vulnerability_exploit',
                    'session_id': session_id,
                    'vulnerability_id': vuln.get('vulnerability_id', ''),
                    'description': f'FTP vulnerability exploitation: {vuln.get("vulnerability_id", "")}',
                    'severity': vuln.get('severity', 'high')
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x.get('timestamp', ''))
        
        return timeline
    
    def _generate_threat_intelligence(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate FTP threat intelligence analysis"""
        intelligence = {
            'ftp_attack_attribution': self._analyze_ftp_attack_attribution(session_data),
            'campaign_analysis': self._analyze_ftp_campaigns(session_data),
            'threat_actor_profiling': self._profile_ftp_threat_actors(session_data),
            'infrastructure_analysis': self._analyze_ftp_infrastructure(session_data)
        }
        
        return intelligence
    
    def _generate_forensic_analysis(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate forensic analysis section for FTP"""
        forensics = {
            'evidence_summary': self._summarize_ftp_evidence(session_data),
            'chain_of_custody': self._analyze_ftp_chain_of_custody(session_data),
            'artifact_analysis': self._analyze_ftp_artifacts(session_data),
            'digital_fingerprints': self._extract_ftp_digital_fingerprints(session_data)
        }
        
        return forensics
    
    def _generate_iocs(self, session_data: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Generate FTP Indicators of Compromise"""
        iocs = {
            'ip_addresses': [],
            'ftp_commands': [],
            'file_hashes': [],
            'usernames': [],
            'attack_signatures': [],
            'malicious_files': []
        }
        
        # Extract IP addresses
        for session in session_data:
            forensic_data = session.get('forensic_data', {})
            for event in forensic_data.get('events', []):
                if event.get('event_type') == 'connection_established':
                    src_ip = event.get('data', {}).get('src_ip')
                    if src_ip and src_ip not in iocs['ip_addresses']:
                        iocs['ip_addresses'].append(src_ip)
        
        # Extract file hashes
        for session in session_data:
            for file_info in session.get('files_downloaded', []):
                file_hash = file_info.get('file_hash')
                if file_hash and file_hash not in iocs['file_hashes']:
                    iocs['file_hashes'].append(file_hash)
            
            for file_info in session.get('files_uploaded', []):
                file_hash = file_info.get('file_hash')
                if file_hash and file_hash not in iocs['file_hashes']:
                    iocs['file_hashes'].append(file_hash)
        
        # Extract suspicious FTP commands
        suspicious_commands = set()
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                command = attack.get('command', '')
                if command and len(command) > 5:  # Filter out short commands
                    suspicious_commands.add(command)
        
        iocs['ftp_commands'] = list(suspicious_commands)[:50]  # Limit to top 50
        
        return iocs
    
    def _generate_recommendations(self, session_data: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Generate FTP security recommendations using integrated JSON data"""
        recommendations = {
            'immediate_actions': [],
            'short_term_improvements': [],
            'long_term_strategy': [],
            'monitoring_enhancements': []
        }
        
        # Analyze attack patterns to generate recommendations
        attack_types = Counter()
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                for attack_type in attack.get('attack_types', []):
                    attack_types[attack_type] += 1
        
        # Generate recommendations based on observed FTP attacks
        if 'directory_traversal' in attack_types:
            recommendations['immediate_actions'].append(
                "Implement strict directory access controls and path validation"
            )
            recommendations['monitoring_enhancements'].append(
                "Deploy FTP traffic monitoring to detect directory traversal attempts"
            )
        
        if 'ftp_bounce_attack' in attack_types:
            recommendations['immediate_actions'].append(
                "Disable FTP bounce attacks by restricting PORT command usage"
            )
            recommendations['short_term_improvements'].append(
                "Implement firewall rules to prevent FTP bounce attacks"
            )
        
        if 'brute_force_authentication' in attack_types:
            recommendations['immediate_actions'].append(
                "Implement account lockout policies and rate limiting"
            )
            recommendations['short_term_improvements'].append(
                "Deploy multi-factor authentication for FTP access"
            )
        
        if 'malicious_file_upload' in attack_types:
            recommendations['immediate_actions'].append(
                "Implement file type restrictions and malware scanning"
            )
            recommendations['monitoring_enhancements'].append(
                "Monitor all file uploads for malicious content"
            )
        
        # General FTP security recommendations
        recommendations['short_term_improvements'].extend([
            "Migrate to SFTP or FTPS for encrypted file transfers",
            "Implement proper access controls and user permissions",
            "Deploy intrusion detection systems for FTP traffic",
            "Regular security audits of FTP server configurations"
        ])
        
        recommendations['long_term_strategy'].extend([
            "Phase out legacy FTP in favor of secure alternatives",
            "Implement zero-trust file sharing architecture",
            "Establish comprehensive file transfer monitoring",
            "Develop incident response procedures for FTP attacks"
        ])
        
        return recommendations
    
    def _generate_appendix(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate appendix with detailed FTP data"""
        return {
            'session_details': [
                {
                    'session_id': s.get('session_id'),
                    'start_time': s.get('start_time'),
                    'end_time': s.get('end_time'),
                    'duration': s.get('duration'),
                    'command_count': len(s.get('commands', [])),
                    'attack_count': len(s.get('attack_analysis', [])),
                    'vulnerability_count': len(s.get('vulnerabilities', []))
                } for s in session_data
            ],
            'ftp_attack_taxonomy': self._get_ftp_attack_taxonomy(),
            'vulnerability_database': self._get_ftp_vulnerability_database()
        }
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML report for FTP honeypot"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEXUS FTP Honeypot Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #2c3e50; margin: 0; font-size: 2.5em; }}
        .header p {{ color: #7f8c8d; margin: 10px 0 0 0; font-size: 1.1em; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #34495e; border-left: 5px solid #e67e22; padding-left: 15px; margin-bottom: 20px; }}
        .section h3 {{ color: #2c3e50; margin-top: 25px; margin-bottom: 15px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: linear-gradient(135deg, #e67e22 0%, #d35400 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-card h3 {{ margin: 0 0 10px 0; font-size: 2em; }}
        .stat-card p {{ margin: 0; opacity: 0.9; }}
        .severity-high {{ color: #e74c3c; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; font-weight: bold; }}
        .severity-low {{ color: #27ae60; font-weight: bold; }}
        .severity-critical {{ color: #8e44ad; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .recommendations {{ background-color: #ecf0f1; padding: 20px; border-radius: 10px; }}
        .recommendations ul {{ margin: 10px 0; }}
        .recommendations li {{ margin-bottom: 8px; }}
        .footer {{ text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid #bdc3c7; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📁 NEXUS FTP Honeypot Security Report</h1>
            <p>Generated on {report_date} | Report ID: {report_id}</p>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{total_sessions}</h3>
                    <p>Total FTP Sessions</p>
                </div>
                <div class="stat-card">
                    <h3>{total_attacks}</h3>
                    <p>Attack Attempts</p>
                </div>
                <div class="stat-card">
                    <h3>{total_vulnerabilities}</h3>
                    <p>Vulnerability Exploits</p>
                </div>
                <div class="stat-card">
                    <h3>{unique_ips}</h3>
                    <p>Unique Source IPs</p>
                </div>
            </div>
            
            <h3>🎯 Key Findings</h3>
            <ul>
                {key_findings}
            </ul>
        </div>
        
        <div class="section">
            <h2>🔍 FTP Attack Analysis</h2>
            <h3>Top Attack Types</h3>
            <table>
                <tr><th>Attack Type</th><th>Count</th><th>Percentage</th></tr>
                {attack_types_table}
            </table>
        </div>
        
        <div class="section">
            <h2>⚠️ Threat Intelligence</h2>
            <h3>Indicators of Compromise (IOCs)</h3>
            <p><strong>Malicious IP Addresses:</strong> {malicious_ips}</p>
            <p><strong>Suspicious File Hashes:</strong> {file_hashes_count} unique hashes identified</p>
            <p><strong>FTP Attack Signatures:</strong> {attack_signatures_count} patterns detected</p>
            <p><strong>Threat Intelligence:</strong> {attack_patterns_count} attack patterns, {vuln_signatures_count} vulnerability signatures integrated</p>
        </div>
        
        <div class="section recommendations">
            <h2>🛠️ Security Recommendations</h2>
            <h3>Immediate Actions Required</h3>
            <ul>
                {immediate_actions}
            </ul>
            
            <h3>Short-term Improvements</h3>
            <ul>
                {short_term_improvements}
            </ul>
        </div>
        
        <div class="footer">
            <p>This report was generated by the NEXUS AI-Enhanced FTP Honeypot System</p>
            <p>For questions or additional analysis, contact the security team</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Extract data for template
        metadata = report.get('metadata', {})
        exec_summary = report.get('executive_summary', {})
        overview = exec_summary.get('overview', {})
        threat_landscape = exec_summary.get('threat_landscape', {})
        iocs = report.get('iocs', {})
        recommendations = report.get('recommendations', {})
        
        # Format data
        key_findings_html = '\n'.join(f'<li>{finding}</li>' for finding in exec_summary.get('key_findings', []))
        
        attack_types = threat_landscape.get('top_attack_types', {})
        total_attack_count = sum(attack_types.values()) if attack_types else 1
        attack_types_table = '\n'.join([
            f'<tr><td>{attack_type}</td><td>{count}</td><td>{count/total_attack_count*100:.1f}%</td></tr>'
            for attack_type, count in attack_types.items()
        ])
        
        immediate_actions_html = '\n'.join(f'<li>{action}</li>' for action in recommendations.get('immediate_actions', []))
        short_term_improvements_html = '\n'.join(f'<li>{improvement}</li>' for improvement in recommendations.get('short_term_improvements', []))
        
        return html_template.format(
            report_date=metadata.get('report_generated', ''),
            report_id=metadata.get('report_id', ''),
            total_sessions=overview.get('total_sessions', 0),
            total_attacks=overview.get('total_attack_attempts', 0),
            total_vulnerabilities=overview.get('total_vulnerability_exploits', 0),
            unique_ips=overview.get('unique_source_ips', 0),
            key_findings=key_findings_html,
            attack_types_table=attack_types_table,
            malicious_ips=len(iocs.get('ip_addresses', [])),
            file_hashes_count=len(iocs.get('file_hashes', [])),
            attack_signatures_count=len(iocs.get('attack_signatures', [])),
            attack_patterns_count=len(self.attack_patterns),
            vuln_signatures_count=len(self.vulnerability_signatures),
            immediate_actions=immediate_actions_html,
            short_term_improvements=short_term_improvements_html
        )
    
    def _generate_visualizations(self, session_data: List[Dict[str, Any]], output_dir: Path):
        """Generate visualization charts for FTP data"""
        try:
            # Set style
            plt.style.use('seaborn-v0_8')
            sns.set_palette("husl")
            
            # FTP Attack types distribution
            attack_types = Counter()
            for session in session_data:
                for attack in session.get('attack_analysis', []):
                    for attack_type in attack.get('attack_types', []):
                        attack_types[attack_type] += 1
            
            if attack_types:
                plt.figure(figsize=(12, 8))
                types, counts = zip(*attack_types.most_common(10))
                plt.bar(types, counts, color='#e67e22')
                plt.title('Top 10 FTP Attack Types', fontsize=16, fontweight='bold')
                plt.xlabel('Attack Type', fontsize=12)
                plt.ylabel('Count', fontsize=12)
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                plt.savefig(output_dir / 'ftp_attack_types_distribution.png', dpi=300, bbox_inches='tight')
                plt.close()
            
            # FTP Command distribution
            all_commands = []
            for session in session_data:
                for cmd in session.get('commands', []):
                    command = cmd.get('command', '').split()[0].upper()
                    if command:
                        all_commands.append(command)
            
            if all_commands:
                command_counts = Counter(all_commands)
                plt.figure(figsize=(12, 8))
                commands, counts = zip(*command_counts.most_common(10))
                plt.bar(commands, counts, color='#d35400')
                plt.title('Top 10 FTP Commands Used', fontsize=16, fontweight='bold')
                plt.xlabel('FTP Command', fontsize=12)
                plt.ylabel('Count', fontsize=12)
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                plt.savefig(output_dir / 'ftp_commands_distribution.png', dpi=300, bbox_inches='tight')
                plt.close()
            
        except Exception as e:
            print(f"Error generating FTP visualizations: {e}")
    
    # Helper methods for FTP-specific analysis
    def _calculate_analysis_period(self, session_data: List[Dict[str, Any]]) -> int:
        """Calculate analysis period in days"""
        if not session_data:
            return 0
        
        start_times = [s.get('start_time', '') for s in session_data if s.get('start_time')]
        if not start_times:
            return 0
        
        try:
            earliest = min(datetime.datetime.fromisoformat(t.replace('Z', '+00:00')) for t in start_times)
            latest = max(datetime.datetime.fromisoformat(t.replace('Z', '+00:00')) for t in start_times)
            return (latest - earliest).days + 1
        except:
            return 0
    
    def _generate_key_findings(self, session_data: List[Dict[str, Any]]) -> List[str]:
        """Generate key findings from FTP analysis"""
        findings = []
        
        # Analyze FTP attack patterns
        attack_types = Counter()
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                for attack_type in attack.get('attack_types', []):
                    attack_types[attack_type] += 1
        
        if 'directory_traversal' in attack_types:
            findings.append(f"Directory traversal attacks detected ({attack_types['directory_traversal']} instances)")
        
        if 'ftp_bounce_attack' in attack_types:
            findings.append(f"FTP bounce attacks identified ({attack_types['ftp_bounce_attack']} instances)")
        
        if 'brute_force_authentication' in attack_types:
            findings.append(f"Brute force authentication attempts ({attack_types['brute_force_authentication']} instances)")
        
        # Analyze file operations
        download_count = sum(len(s.get('files_downloaded', [])) for s in session_data)
        upload_count = sum(len(s.get('files_uploaded', [])) for s in session_data)
        
        if download_count > 0:
            findings.append(f"Suspicious file downloads attempted ({download_count} files)")
        
        if upload_count > 0:
            findings.append(f"Malicious file uploads detected ({upload_count} files)")
        
        if not findings:
            findings.append("No significant FTP security threats detected during analysis period")
        
        return findings
    
    def _assess_risk_level(self, session_data: List[Dict[str, Any]]) -> str:
        """Assess overall FTP risk level"""
        risk_score = 0
        
        # Count critical and high severity attacks
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                severity = attack.get('severity', 'low')
                if severity == 'critical':
                    risk_score += 10
                elif severity == 'high':
                    risk_score += 5
                elif severity == 'medium':
                    risk_score += 2
                elif severity == 'low':
                    risk_score += 1
        
        # Assess vulnerability exploits
        vuln_count = sum(len(s.get('vulnerabilities', [])) for s in session_data)
        risk_score += vuln_count * 5
        
        # Determine risk level
        if risk_score >= 100:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 20:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _categorize_ftp_commands(self, commands: List[str]) -> Dict[str, int]:
        """Categorize FTP commands by type"""
        categories = {
            'authentication': 0,
            'navigation': 0,
            'file_transfer': 0,
            'directory_listing': 0,
            'system_commands': 0,
            'other': 0
        }
        
        auth_commands = ['USER', 'PASS', 'ACCT']
        nav_commands = ['CWD', 'CDUP', 'PWD']
        transfer_commands = ['RETR', 'STOR', 'APPE', 'REST']
        listing_commands = ['LIST', 'NLST', 'STAT']
        system_commands = ['SYST', 'HELP', 'NOOP', 'QUIT', 'SITE']
        
        for cmd in commands:
            cmd_base = cmd.split()[0].upper() if cmd.split() else ''
            
            if cmd_base in auth_commands:
                categories['authentication'] += 1
            elif cmd_base in nav_commands:
                categories['navigation'] += 1
            elif cmd_base in transfer_commands:
                categories['file_transfer'] += 1
            elif cmd_base in listing_commands:
                categories['directory_listing'] += 1
            elif cmd_base in system_commands:
                categories['system_commands'] += 1
            else:
                categories['other'] += 1
        
        return categories
    
    # FTP-specific analysis methods
    def _analyze_ftp_attack_vectors(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze FTP attack vectors"""
        vectors = {}
        for attack_type, attack_data in self.attack_patterns.items():
            count = 0
            for session in session_data:
                for attack in session.get('attack_analysis', []):
                    if attack_type in attack.get('attack_types', []):
                        count += 1
            if count > 0:
                vectors[attack_type] = {
                    'count': count,
                    'description': attack_data.get('description', ''),
                    'severity': attack_data.get('severity', 'medium'),
                    'indicators': attack_data.get('indicators', [])
                }
        return {'ftp_attack_vectors': vectors, 'total_vectors': len(vectors)}
    
    def _analyze_directory_traversal(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze directory traversal attempts"""
        traversal_attempts = 0
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                if 'directory_traversal' in attack.get('attack_types', []):
                    traversal_attempts += 1
        
        return {
            'total_attempts': traversal_attempts,
            'severity': 'high' if traversal_attempts > 0 else 'low',
            'description': 'Attempts to access files outside allowed directories'
        }
    
    def _analyze_bounce_attacks(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze FTP bounce attacks"""
        bounce_attempts = 0
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                if 'ftp_bounce_attack' in attack.get('attack_types', []):
                    bounce_attempts += 1
        
        return {
            'total_attempts': bounce_attempts,
            'severity': 'critical' if bounce_attempts > 0 else 'low',
            'description': 'FTP bounce attacks using PORT command'
        }
    
    def _analyze_brute_force(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze brute force attempts"""
        brute_force_attempts = 0
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                if 'brute_force_authentication' in attack.get('attack_types', []):
                    brute_force_attempts += 1
        
        return {
            'total_attempts': brute_force_attempts,
            'severity': 'high' if brute_force_attempts > 0 else 'low',
            'description': 'Brute force authentication attempts'
        }
    
    def _analyze_malicious_uploads(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze malicious file uploads"""
        malicious_uploads = 0
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                if 'malicious_file_upload' in attack.get('attack_types', []):
                    malicious_uploads += 1
        
        return {
            'total_uploads': malicious_uploads,
            'severity': 'critical' if malicious_uploads > 0 else 'low',
            'description': 'Upload of potentially malicious files'
        }
    
    # Additional FTP-specific methods would be implemented here...
    def _analyze_ftp_attack_attribution(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze FTP attack attribution"""
        return {'confidence_level': 'low', 'potential_groups': [], 'techniques_used': []}
    
    def _analyze_ftp_campaigns(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze FTP attack campaigns"""
        return {'potential_campaigns': 0, 'campaign_details': {}}
    
    def _profile_ftp_threat_actors(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Profile FTP threat actors"""
        return {'skill_level': 'unknown', 'motivation': 'unknown'}
    
    def _analyze_ftp_infrastructure(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze FTP attacker infrastructure"""
        return {'unique_ips': [], 'total_unique_ips': 0}
    
    def _summarize_ftp_evidence(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize FTP forensic evidence"""
        return {'total_sessions': len(session_data), 'evidence_files': 0}
    
    def _analyze_ftp_chain_of_custody(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze FTP forensic chain of custody"""
        return {'valid_chains': 0, 'evidence_integrity': 'unknown'}
    
    def _analyze_ftp_artifacts(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze FTP digital artifacts"""
        return {'file_artifacts': [], 'command_artifacts': [], 'total_artifacts': 0}
    
    def _extract_ftp_digital_fingerprints(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract FTP digital fingerprints"""
        return {'command_patterns': {}, 'unique_fingerprints': 0}
    
    def _get_ftp_attack_taxonomy(self) -> Dict[str, Any]:
        """Return FTP attack taxonomy"""
        return self.attack_patterns
    
    def _get_ftp_vulnerability_database(self) -> Dict[str, Any]:
        """Return FTP vulnerability database"""
        return self.vulnerability_signatures

if __name__ == "__main__":
    # Example usage
    generator = FTPHoneypotReportGenerator()
    report_files = generator.generate_comprehensive_report()
    print(f"FTP Reports generated: {report_files}")