#!/usr/bin/env python3
"""
AI-Enhanced Honeypot Report Generator
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

class HoneypotReportGenerator:
    """Generate comprehensive reports from honeypot session data with integrated JSON threat intelligence"""
    
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
            with open(patterns_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load attack patterns: {e}")
            return {}
            
    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures from JSON configuration"""
        try:
            vuln_file = Path(__file__).parent / "vulnerability_signatures.json"
            with open(vuln_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load vulnerability signatures: {e}")
            return {}
        
    def generate_comprehensive_report(self, output_dir: str = "reports") -> Dict[str, str]:
        """Generate a comprehensive security report"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Collect all session data
        session_data = self._collect_session_data()
        
        if not session_data:
            return {"error": "No session data found"}
        
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
        json_file = output_path / f"honeypot_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        report_files['json'] = str(json_file)
        
        # HTML Report
        html_file = output_path / f"honeypot_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_content = self._generate_html_report(report)
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        report_files['html'] = str(html_file)
        
        # Generate visualizations
        viz_dir = output_path / "visualizations"
        viz_dir.mkdir(exist_ok=True)
        self._generate_visualizations(session_data, viz_dir)
        
        return report_files
    
    def _collect_session_data(self) -> List[Dict[str, Any]]:
        """Collect data from all session directories"""
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
                        with open(session_file, 'r', encoding='utf-8') as f:
                            session_info.update(json.load(f))
                    except Exception as e:
                        print(f"Error loading session {session_dir.name}: {e}")
                        continue
                
                # Load forensic data
                if forensic_file.exists():
                    try:
                        with open(forensic_file, 'r', encoding='utf-8') as f:
                            forensic_data = json.load(f)
                            session_info['forensic_data'] = forensic_data
                    except Exception as e:
                        print(f"Error loading forensic data for {session_dir.name}: {e}")
                
                session_data.append(session_info)
        
        print(f"Loaded {len(session_data)} sessions from {self.sessions_dir}")
        return session_data
    
    def _generate_metadata(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate report metadata"""
        return {
            'report_generated': datetime.datetime.now().isoformat(),
            'report_version': '1.0',
            'honeypot_type': 'SSH AI-Enhanced Medium Interaction',
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
        """Generate executive summary"""
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
        """Generate detailed attack statistics"""
        stats = {
            'command_analysis': {},
            'attack_patterns': {},
            'temporal_analysis': {},
            'geographic_analysis': {},
            'file_operations': {}
        }
        
        # Command analysis
        all_commands = []
        for session in session_data:
            for cmd in session.get('commands', []):
                all_commands.append(cmd.get('command', ''))
        
        command_counter = Counter(all_commands)
        stats['command_analysis'] = {
            'total_commands': len(all_commands),
            'unique_commands': len(command_counter),
            'most_common_commands': dict(command_counter.most_common(20)),
            'command_categories': self._categorize_commands(all_commands)
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
            'file_creations': 0
        }
        
        for session in session_data:
            file_ops['downloads'] += len(session.get('files_downloaded', []))
            file_ops['uploads'] += len(session.get('files_uploaded', []))
        
        stats['file_operations'] = file_ops
        
        return stats
    
    def _generate_technical_analysis(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate technical analysis section"""
        analysis = {
            'attack_vectors': self._analyze_attack_vectors(session_data),
            'exploitation_techniques': self._analyze_exploitation_techniques(session_data),
            'persistence_mechanisms': self._analyze_persistence_mechanisms(session_data),
            'evasion_techniques': self._analyze_evasion_techniques(session_data),
            'tool_signatures': self._identify_tool_signatures(session_data)
        }
        
        return analysis
    
    def _generate_attack_timeline(self, session_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate chronological attack timeline"""
        timeline = []
        
        for session in session_data:
            session_id = session.get('session_id', 'unknown')
            start_time = session.get('start_time', '')
            
            # Add session start
            timeline.append({
                'timestamp': start_time,
                'event_type': 'session_start',
                'session_id': session_id,
                'description': f'New SSH session initiated',
                'severity': 'info'
            })
            
            # Add commands and attacks
            for cmd in session.get('commands', []):
                timeline.append({
                    'timestamp': cmd.get('timestamp', ''),
                    'event_type': 'command_execution',
                    'session_id': session_id,
                    'command': cmd.get('command', ''),
                    'description': f'Command executed: {cmd.get("command", "")[:50]}...',
                    'severity': 'low'
                })
            
            # Add attack events
            for attack in session.get('attack_analysis', []):
                if attack.get('attack_types'):
                    timeline.append({
                        'timestamp': attack.get('timestamp', ''),
                        'event_type': 'attack_detected',
                        'session_id': session_id,
                        'attack_types': attack.get('attack_types', []),
                        'description': f'Attack detected: {", ".join(attack.get("attack_types", []))}',
                        'severity': attack.get('severity', 'medium')
                    })
            
            # Add vulnerability exploits
            for vuln in session.get('vulnerabilities', []):
                timeline.append({
                    'timestamp': vuln.get('timestamp', ''),
                    'event_type': 'vulnerability_exploit',
                    'session_id': session_id,
                    'vulnerability_id': vuln.get('vulnerability_id', ''),
                    'description': f'Vulnerability exploitation: {vuln.get("vulnerability_id", "")}',
                    'severity': vuln.get('severity', 'high')
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x.get('timestamp', ''))
        
        return timeline
    
    def _generate_threat_intelligence(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate threat intelligence analysis"""
        intelligence = {
            'attack_attribution': self._analyze_attack_attribution(session_data),
            'campaign_analysis': self._analyze_campaigns(session_data),
            'threat_actor_profiling': self._profile_threat_actors(session_data),
            'infrastructure_analysis': self._analyze_infrastructure(session_data)
        }
        
        return intelligence
    
    def _generate_forensic_analysis(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate forensic analysis section"""
        forensics = {
            'evidence_summary': self._summarize_evidence(session_data),
            'chain_of_custody': self._analyze_chain_of_custody(session_data),
            'artifact_analysis': self._analyze_artifacts(session_data),
            'digital_fingerprints': self._extract_digital_fingerprints(session_data)
        }
        
        return forensics
    
    def _generate_iocs(self, session_data: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Generate Indicators of Compromise"""
        iocs = {
            'ip_addresses': [],
            'domains': [],
            'file_hashes': [],
            'command_patterns': [],
            'user_agents': [],
            'attack_signatures': []
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
        
        # Extract command patterns
        suspicious_commands = set()
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                command = attack.get('command', '')
                if command and len(command) > 10:  # Filter out short commands
                    suspicious_commands.add(command)
        
        iocs['command_patterns'] = list(suspicious_commands)[:50]  # Limit to top 50
        
        return iocs
    
    def _generate_recommendations(self, session_data: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Generate security recommendations using integrated JSON data"""
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
        
        # Generate recommendations based on observed attacks using integrated JSON data
        if 'reconnaissance' in attack_types:
            recon_data = self.attack_patterns.get('reconnaissance', {})
            recommendations['immediate_actions'].append(
                "Implement network segmentation to limit reconnaissance scope"
            )
            recommendations['monitoring_enhancements'].append(
                "Deploy network monitoring tools to detect reconnaissance activities"
            )
            if recon_data.get('severity') == 'high':
                recommendations['immediate_actions'].append(
                    "Review and restrict access to system information disclosure points"
                )
        
        if 'privilege_escalation' in attack_types:
            privesc_data = self.attack_patterns.get('privilege_escalation', {})
            recommendations['immediate_actions'].append(
                "Review and harden sudo configurations and SUID binaries"
            )
            recommendations['short_term_improvements'].append(
                "Implement privilege access management (PAM) solutions"
            )
            if privesc_data.get('severity') in ['high', 'critical']:
                recommendations['immediate_actions'].append(
                    "Conduct emergency audit of privileged accounts and access controls"
                )
        
        if 'persistence' in attack_types:
            persist_data = self.attack_patterns.get('persistence', {})
            recommendations['immediate_actions'].append(
                "Audit cron jobs, startup scripts, and SSH authorized keys"
            )
            recommendations['monitoring_enhancements'].append(
                "Monitor file system changes and process creation events"
            )
            if persist_data.get('severity') == 'critical':
                recommendations['immediate_actions'].append(
                    "Immediately review all system startup mechanisms and scheduled tasks"
                )
        
        if 'data_exfiltration' in attack_types:
            recommendations['immediate_actions'].append(
                "Implement data loss prevention (DLP) controls"
            )
            recommendations['short_term_improvements'].append(
                "Deploy network traffic analysis tools"
            )
        
        # General recommendations
        recommendations['short_term_improvements'].extend([
            "Implement multi-factor authentication for all administrative accounts",
            "Deploy endpoint detection and response (EDR) solutions",
            "Establish security information and event management (SIEM) system",
            "Conduct regular vulnerability assessments and penetration testing"
        ])
        
        recommendations['long_term_strategy'].extend([
            "Develop and maintain an incident response plan",
            "Implement zero-trust network architecture",
            "Establish threat intelligence program",
            "Conduct regular security awareness training"
        ])
        
        return recommendations
    
    def _generate_appendix(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate appendix with detailed data"""
        return {
            'session_details': [{
                'session_id': s.get('session_id'),
                'start_time': s.get('start_time'),
                'end_time': s.get('end_time'),
                'duration': s.get('duration'),
                'command_count': len(s.get('commands', [])),
                'attack_count': len(s.get('attack_analysis', [])),
                'vulnerability_count': len(s.get('vulnerabilities', []))
            } for s in session_data],
            'attack_taxonomy': self._get_attack_taxonomy(),
            'vulnerability_database': self._get_vulnerability_database()
        }
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEXUS AI Honeypot Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #2c3e50; margin: 0; font-size: 2.5em; }}
        .header p {{ color: #7f8c8d; margin: 10px 0 0 0; font-size: 1.1em; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #34495e; border-left: 5px solid #3498db; padding-left: 15px; margin-bottom: 20px; }}
        .section h3 {{ color: #2c3e50; margin-top: 25px; margin-bottom: 15px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
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
        .timeline-item {{ border-left: 3px solid #3498db; padding-left: 20px; margin-bottom: 20px; }}
        .timeline-item.critical {{ border-left-color: #8e44ad; }}
        .timeline-item.high {{ border-left-color: #e74c3c; }}
        .timeline-item.medium {{ border-left-color: #f39c12; }}
        .timeline-item.low {{ border-left-color: #27ae60; }}
        .recommendations {{ background-color: #ecf0f1; padding: 20px; border-radius: 10px; }}
        .recommendations ul {{ margin: 10px 0; }}
        .recommendations li {{ margin-bottom: 8px; }}
        .footer {{ text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid #bdc3c7; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ NEXUS AI Honeypot Security Report</h1>
            <p>Generated on {report_date} | Report ID: {report_id}</p>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{total_sessions}</h3>
                    <p>Total Sessions</p>
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
            <h2>🔍 Attack Analysis</h2>
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
            <p><strong>Attack Signatures:</strong> {attack_signatures_count} patterns detected</p>
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
            <p>This report was generated by the NEXUS AI-Enhanced Honeypot System</p>
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
    
    # amazonq-ignore-next-line
    def _generate_visualizations(self, session_data: List[Dict[str, Any]], output_dir: Path):
        """Generate visualization charts"""
        try:
            # Set style
            plt.style.use('seaborn-v0_8')
            sns.set_palette("husl")
            
            # Attack types distribution
            attack_types = Counter()
            for session in session_data:
                for attack in session.get('attack_analysis', []):
                    for attack_type in attack.get('attack_types', []):
                        attack_types[attack_type] += 1
            
            if attack_types:
                plt.figure(figsize=(12, 8))
                types, counts = zip(*attack_types.most_common(10))
                plt.bar(types, counts)
                plt.title('Top 10 Attack Types', fontsize=16, fontweight='bold')
                plt.xlabel('Attack Type', fontsize=12)
                plt.ylabel('Count', fontsize=12)
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                plt.savefig(output_dir / 'attack_types_distribution.png', dpi=300, bbox_inches='tight')
                plt.close()
            
            # Severity distribution pie chart
            severity_counts = Counter()
            for session in session_data:
                for attack in session.get('attack_analysis', []):
                    severity_counts[attack.get('severity', 'unknown')] += 1
            
            if severity_counts:
                plt.figure(figsize=(10, 8))
                labels, sizes = zip(*severity_counts.items())
                colors = ['#e74c3c', '#f39c12', '#f1c40f', '#27ae60', '#95a5a6']
                plt.pie(sizes, labels=labels, colors=colors[:len(labels)], autopct='%1.1f%%', startangle=90)
                plt.title('Attack Severity Distribution', fontsize=16, fontweight='bold')
                plt.axis('equal')
                plt.tight_layout()
                plt.savefig(output_dir / 'severity_distribution.png', dpi=300, bbox_inches='tight')
                plt.close()
            
            # Timeline visualization
            if session_data:
                session_times = []
                for session in session_data:
                    start_time = session.get('start_time', '')
                    if start_time:
                        try:
                            dt = datetime.datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                            session_times.append(dt)
                        except:
                            continue
                
                if session_times:
                    plt.figure(figsize=(14, 6))
                    session_times.sort()
                    dates = [dt.date() for dt in session_times]
                    date_counts = Counter(dates)
                    
                    dates_list, counts_list = zip(*sorted(date_counts.items()))
                    plt.plot(dates_list, counts_list, marker='o', linewidth=2, markersize=6)
                    plt.title('Attack Sessions Over Time', fontsize=16, fontweight='bold')
                    plt.xlabel('Date', fontsize=12)
                    plt.ylabel('Number of Sessions', fontsize=12)
                    plt.xticks(rotation=45)
                    plt.grid(True, alpha=0.3)
                    plt.tight_layout()
                    plt.savefig(output_dir / 'attack_timeline.png', dpi=300, bbox_inches='tight')
                    plt.close()
            
        except Exception as e:
            print(f"Error generating visualizations: {e}")
    
    # Helper methods for analysis
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
    
    def _extract_attack_counts(self, session_data: List[Dict[str, Any]]) -> Counter:
        """Extract attack type counts from session data"""
        attack_types = Counter()
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                for attack_type in attack.get('attack_types', []):
                    attack_types[attack_type] += 1
        return attack_types
    
    def _extract_critical_vulnerabilities(self, session_data: List[Dict[str, Any]]) -> List[str]:
        """Extract critical vulnerability names from session data"""
        critical_vulns = []
        for session in session_data:
            for vuln in session.get('vulnerabilities', []):
                vuln_id = vuln.get('vulnerability_id', '')
                if vuln_id in self.vulnerability_signatures:
                    vuln_data = self.vulnerability_signatures[vuln_id]
                    if vuln_data.get('severity') == 'critical':
                        critical_vulns.append(vuln_data.get('name', vuln_id))
        return list(set(critical_vulns))
    
    def _generate_key_findings(self, session_data: List[Dict[str, Any]]) -> List[str]:
        """Generate key findings from analysis using integrated JSON data"""
        findings = []
        
        # Get attack counts
        attack_types = self._extract_attack_counts(session_data)
        
        # Check for high-volume attacks
        if attack_types.get('reconnaissance', 0) > 5:
            findings.append(f"High volume of reconnaissance activities detected ({attack_types['reconnaissance']} instances)")
        
        if 'privilege_escalation' in attack_types:
            findings.append(f"Privilege escalation attempts identified ({attack_types['privilege_escalation']} instances)")
        
        if 'persistence' in attack_types:
            findings.append(f"Persistence mechanisms deployed by attackers ({attack_types['persistence']} instances)")
        
        # Check vulnerabilities
        vuln_count = sum(len(s.get('vulnerabilities', [])) for s in session_data)
        if vuln_count > 0:
            findings.append(f"Multiple vulnerability exploitation attempts detected ({vuln_count} total)")
            
            critical_vulns = self._extract_critical_vulnerabilities(session_data)
            if critical_vulns:
                findings.append(f"Critical vulnerabilities targeted: {', '.join(critical_vulns[:3])}{'...' if len(critical_vulns) > 3 else ''}")
        
        # Check file operations
        download_count = sum(len(s.get('files_downloaded', [])) for s in session_data)
        upload_count = sum(len(s.get('files_uploaded', [])) for s in session_data)
        
        if download_count > 0:
            findings.append(f"Malicious file downloads attempted ({download_count} files)")
        
        if upload_count > 0:
            findings.append(f"Suspicious file uploads detected ({upload_count} files)")
        
        if not findings:
            findings.append("No significant security threats detected during analysis period")
        
        return findings
    
    def _assess_risk_level(self, session_data: List[Dict[str, Any]]) -> str:
        """Assess overall risk level"""
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
    
    def _categorize_commands(self, commands: List[str]) -> Dict[str, int]:
        """Categorize commands by type"""
        categories = {
            'reconnaissance': 0,
            'file_operations': 0,
            'network_operations': 0,
            'system_administration': 0,
            'other': 0
        }
        
        recon_commands = ['whoami', 'id', 'uname', 'ps', 'netstat', 'ss', 'ifconfig', 'ip', 'w', 'who', 'last']
        file_commands = ['ls', 'cat', 'find', 'locate', 'head', 'tail', 'grep', 'cp', 'mv', 'rm']
        network_commands = ['wget', 'curl', 'nc', 'netcat', 'ssh', 'scp', 'ping', 'traceroute']
        admin_commands = ['sudo', 'su', 'systemctl', 'service', 'crontab', 'mount', 'umount']
        
        for cmd in commands:
            cmd_base = cmd.split()[0] if cmd.split() else ''
            
            if cmd_base in recon_commands:
                categories['reconnaissance'] += 1
            elif cmd_base in file_commands:
                categories['file_operations'] += 1
            elif cmd_base in network_commands:
                categories['network_operations'] += 1
            elif cmd_base in admin_commands:
                categories['system_administration'] += 1
            else:
                categories['other'] += 1
        
        return categories
    
    # Advanced analysis methods with integrated threat intelligence
    def _analyze_attack_vectors(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attack vectors using integrated threat intelligence"""
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
        return {'attack_vectors': vectors, 'total_vectors': len(vectors)}
    
    def _analyze_exploitation_techniques(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze exploitation techniques from vulnerability data"""
        techniques = {}
        for session in session_data:
            for vuln in session.get('vulnerabilities', []):
                vuln_id = vuln.get('vulnerability_id', '')
                if vuln_id in self.vulnerability_signatures:
                    vuln_data = self.vulnerability_signatures[vuln_id]
                    techniques[vuln_id] = {
                        'name': vuln_data.get('name', vuln_id),
                        'cvss_score': vuln_data.get('cvss_score', 0.0),
                        'severity': vuln_data.get('severity', 'medium'),
                        'description': vuln_data.get('description', '')
                    }
        return {'exploitation_techniques': techniques, 'total_techniques': len(techniques)}
    
    def _analyze_persistence_mechanisms(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze persistence mechanisms from attack patterns"""
        persistence_data = self.attack_patterns.get('persistence', {})
        persistence_count = 0
        
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                if 'persistence' in attack.get('attack_types', []):
                    persistence_count += 1
                    
        return {
            'persistence_attempts': persistence_count,
            'severity': persistence_data.get('severity', 'medium'),
            'indicators': persistence_data.get('indicators', []),
            'description': persistence_data.get('description', '')
        }
    
    def _analyze_evasion_techniques(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze evasion techniques from attack patterns"""
        evasion_data = self.attack_patterns.get('defense_evasion', {})
        evasion_count = 0
        
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                if 'defense_evasion' in attack.get('attack_types', []):
                    evasion_count += 1
                    
        return {
            'evasion_attempts': evasion_count,
            'severity': evasion_data.get('severity', 'medium'),
            'indicators': evasion_data.get('indicators', []),
            'description': evasion_data.get('description', '')
        }
    
    def _identify_tool_signatures(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify tool signatures from command patterns"""
        tool_signatures = {
            'nmap': 0, 'wget': 0, 'curl': 0, 'nc': 0, 'ssh': 0,
            'python': 0, 'perl': 0, 'bash': 0, 'powershell': 0
        }
        
        for session in session_data:
            for cmd in session.get('commands', []):
                command = cmd.get('command', '').lower()
                for tool in tool_signatures.keys():
                    if tool in command:
                        tool_signatures[tool] += 1
                        
        return {'tool_signatures': {k: v for k, v in tool_signatures.items() if v > 0}}
    
    def _analyze_attack_attribution(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attack attribution based on patterns and techniques"""
        attribution = {
            'confidence_level': 'low',
            'potential_groups': [],
            'techniques_used': [],
            'infrastructure_indicators': []
        }
        
        # Analyze techniques used
        techniques = set()
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                techniques.update(attack.get('attack_types', []))
                
        attribution['techniques_used'] = list(techniques)
        
        # Basic attribution logic
        if 'persistence' in techniques and 'privilege_escalation' in techniques:
            attribution['potential_groups'].append('Advanced Persistent Threat (APT)')
            attribution['confidence_level'] = 'medium'
            
        return attribution
    
    def _analyze_campaigns(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze potential attack campaigns"""
        # Group sessions by source IP and time proximity
        campaigns = {}
        for session in session_data:
            forensic_data = session.get('forensic_data', {})
            for event in forensic_data.get('events', []):
                if event.get('event_type') == 'connection_established':
                    src_ip = event.get('data', {}).get('src_ip')
                    if src_ip:
                        if src_ip not in campaigns:
                            campaigns[src_ip] = []
                        campaigns[src_ip].append(session)
                        
        return {
            'potential_campaigns': len([ip for ip, sessions in campaigns.items() if len(sessions) > 1]),
            'campaign_details': {ip: len(sessions) for ip, sessions in campaigns.items() if len(sessions) > 1}
        }
    
    def _profile_threat_actors(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Profile threat actors based on behavior patterns"""
        profiles = {
            'skill_level': 'unknown',
            'motivation': 'unknown',
            'persistence_level': 'low',
            'stealth_level': 'low'
        }
        
        # Analyze skill level based on techniques
        advanced_techniques = ['privilege_escalation', 'persistence', 'defense_evasion']
        technique_count = 0
        
        for session in session_data:
            for attack in session.get('attack_analysis', []):
                for technique in attack.get('attack_types', []):
                    if technique in advanced_techniques:
                        technique_count += 1
                        
        if technique_count > 10:
            profiles['skill_level'] = 'advanced'
        elif technique_count > 5:
            profiles['skill_level'] = 'intermediate'
        else:
            profiles['skill_level'] = 'basic'
            
        return profiles
    
    def _analyze_infrastructure(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attacker infrastructure"""
        infrastructure = {
            'unique_ips': set(),
            'ip_geolocation': {},
            'connection_patterns': {},
            'infrastructure_type': 'unknown'
        }
        
        for session in session_data:
            forensic_data = session.get('forensic_data', {})
            for event in forensic_data.get('events', []):
                if event.get('event_type') == 'connection_established':
                    src_ip = event.get('data', {}).get('src_ip')
                    if src_ip:
                        infrastructure['unique_ips'].add(src_ip)
                        
        infrastructure['unique_ips'] = list(infrastructure['unique_ips'])
        infrastructure['total_unique_ips'] = len(infrastructure['unique_ips'])
        
        return infrastructure
    
    def _summarize_evidence(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize forensic evidence collected"""
        evidence = {
            'total_sessions': len(session_data),
            'evidence_files': 0,
            'forensic_chains': 0,
            'file_artifacts': 0,
            'command_logs': 0
        }
        
        for session in session_data:
            forensic_data = session.get('forensic_data', {})
            evidence['evidence_files'] += len(forensic_data.get('evidence', []))
            evidence['forensic_chains'] += 1 if forensic_data.get('events') else 0
            evidence['file_artifacts'] += len(session.get('files_downloaded', [])) + len(session.get('files_uploaded', []))
            evidence['command_logs'] += len(session.get('commands', []))
            
        return evidence
    
    def _analyze_chain_of_custody(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze forensic chain of custody"""
        custody = {
            'valid_chains': 0,
            'broken_chains': 0,
            'evidence_integrity': 'unknown',
            'total_evidence_items': 0
        }
        
        for session in session_data:
            forensic_data = session.get('forensic_data', {})
            events = forensic_data.get('events', [])
            evidence = forensic_data.get('evidence', [])
            
            if events and evidence:
                custody['valid_chains'] += 1
            else:
                custody['broken_chains'] += 1
                
            custody['total_evidence_items'] += len(evidence)
            
        if custody['valid_chains'] > custody['broken_chains']:
            custody['evidence_integrity'] = 'good'
        else:
            custody['evidence_integrity'] = 'compromised'
            
        return custody
    
    def _analyze_artifacts(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze digital artifacts"""
        artifacts = {
            'file_artifacts': [],
            'command_artifacts': [],
            'network_artifacts': [],
            'total_artifacts': 0
        }
        
        for session in session_data:
            # File artifacts
            for file_info in session.get('files_downloaded', []):
                artifacts['file_artifacts'].append({
                    'type': 'download',
                    'filename': file_info.get('filename', ''),
                    'hash': file_info.get('file_hash', ''),
                    'size': file_info.get('file_size', 0)
                })
                
            for file_info in session.get('files_uploaded', []):
                artifacts['file_artifacts'].append({
                    'type': 'upload',
                    'filename': file_info.get('filename', ''),
                    'hash': file_info.get('file_hash', ''),
                    'size': file_info.get('file_size', 0)
                })
                
            # Command artifacts
            for cmd in session.get('commands', []):
                artifacts['command_artifacts'].append({
                    'command': cmd.get('command', ''),
                    'timestamp': cmd.get('timestamp', ''),
                    'interactive': cmd.get('interactive', False)
                })
                
        artifacts['total_artifacts'] = (len(artifacts['file_artifacts']) + 
                                      len(artifacts['command_artifacts']) + 
                                      len(artifacts['network_artifacts']))
        
        return artifacts
    
    def _extract_digital_fingerprints(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract digital fingerprints from session data"""
        fingerprints = {
            'command_patterns': {},
            'timing_patterns': {},
            'behavioral_patterns': {},
            'unique_fingerprints': 0
        }
        
        # Analyze command patterns
        command_sequences = []
        for session in session_data:
            sequence = []
            for cmd in session.get('commands', []):
                sequence.append(cmd.get('command', '').split()[0] if cmd.get('command', '').split() else '')
            if sequence:
                command_sequences.append(' -> '.join(sequence[:5]))  # First 5 commands
                
        fingerprints['command_patterns'] = dict(Counter(command_sequences))
        fingerprints['unique_fingerprints'] = len(set(command_sequences))
        
        return fingerprints
    
    def _get_attack_taxonomy(self) -> Dict[str, Any]:
        """Return integrated attack taxonomy from JSON data"""
        taxonomy = {}
        for attack_type, attack_data in self.attack_patterns.items():
            taxonomy[attack_type] = {
                'description': attack_data.get('description', ''),
                'severity': attack_data.get('severity', 'medium'),
                'indicators': attack_data.get('indicators', []),
                'pattern_count': len(attack_data.get('patterns', []))
            }
        return taxonomy
    
    def _get_vulnerability_database(self) -> Dict[str, Any]:
        """Return integrated vulnerability database from JSON data"""
        database = {}
        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            database[vuln_id] = {
                'name': vuln_data.get('name', vuln_id),
                'description': vuln_data.get('description', ''),
                'severity': vuln_data.get('severity', 'medium'),
                'cvss_score': vuln_data.get('cvss_score', 0.0),
                'indicators': vuln_data.get('indicators', []),
                'pattern_count': len(vuln_data.get('patterns', []))
            }
        return database

if __name__ == "__main__":
    # Example usage
    generator = HoneypotReportGenerator()
    report_files = generator.generate_comprehensive_report()
    print(f"Reports generated: {report_files}")