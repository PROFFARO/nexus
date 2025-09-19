#!/usr/bin/env python3

import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any
from collections import defaultdict, Counter

class MySQLHoneypotReportGenerator:
    """Generate comprehensive security reports for MySQL honeypot"""
    
    def __init__(self, sessions_dir: str):
        self.sessions_dir = Path(sessions_dir)
        self.report_data = {
            'metadata': {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'sessions_analyzed': 0,
                'total_queries': 0,
                'unique_attackers': 0
            },
            'summary': {},
            'attack_analysis': {},
            'vulnerability_analysis': {},
            'database_operations': {},
            'session_details': []
        }
    
    def generate_comprehensive_report(self, output_dir: str = "reports") -> Dict[str, str]:
        """Generate comprehensive MySQL security report"""
        try:
            # Analyze all sessions
            self._analyze_sessions()
            
            # Generate summary statistics
            self._generate_summary()
            
            # Create output directory
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Generate reports
            json_file = output_path / f"mysql_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            html_file = output_path / f"mysql_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
            # Save JSON report
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(self.report_data, f, indent=2, default=str, ensure_ascii=False)
            
            # Generate HTML report
            try:
                html_content = self._generate_html_report()
                if html_content:
                    with open(html_file, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                else:
                    # Write empty file if content generation failed
                    with open(html_file, 'w', encoding='utf-8') as f:
                        f.write("<html><body><h1>Report generation failed</h1></body></html>")
            except Exception as e:
                # Write error to HTML file
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(f"<html><body><h1>HTML Generation Error</h1><p>{str(e)}</p></body></html>")
            
            return {
                'json': str(json_file),
                'html': str(html_file)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_sessions(self):
        """Analyze all session files"""
        if not self.sessions_dir.exists():
            return
        
        sessions = []
        attackers = set()
        total_queries = 0
        
        for session_dir in self.sessions_dir.iterdir():
            if not session_dir.is_dir():
                continue
            
            # Try multiple session file names for compatibility
            session_files = [
                session_dir / "session_summary.json",
                session_dir / "session_data.json"
            ]
            
            session_data = None
            for session_file in session_files:
                if session_file.exists():
                    try:
                        with open(session_file, 'r', encoding='utf-8') as f:
                            session_data = json.load(f)
                        break
                    except Exception as e:
                        continue
            
            if not session_data:
                continue
                
            sessions.append(session_data)
            
            # Track unique attackers
            client_ip = session_data.get('client_info', {}).get('ip', 'unknown')
            if client_ip != 'unknown':
                attackers.add(client_ip)
            
            # Count queries
            total_queries += len(session_data.get('queries', []))
        
        self.report_data['metadata']['sessions_analyzed'] = len(sessions)
        self.report_data['metadata']['total_queries'] = total_queries
        self.report_data['metadata']['unique_attackers'] = len(attackers)
        self.report_data['session_details'] = sessions
    
    def _generate_summary(self):
        """Generate summary statistics"""
        sessions = self.report_data['session_details']
        
        # Attack statistics
        attack_types = Counter()
        severity_counts = Counter()
        vulnerability_counts = Counter()
        database_operations = Counter()
        
        for session in sessions:
            # Count attack types
            for analysis in session.get('attack_analysis', []):
                for attack_type in analysis.get('attack_types', []):
                    attack_types[attack_type] += 1
                severity_counts[analysis.get('severity', 'unknown')] += 1
            
            # Count vulnerabilities
            for vuln in session.get('vulnerabilities', []):
                vulnerability_counts[vuln.get('vulnerability_id', 'unknown')] += 1
            
            # Count database operations
            database_operations['created_databases'] += len(session.get('created_databases', []))
            database_operations['total_queries'] += session.get('session_stats', {}).get('total_queries', 0)
            database_operations['attack_queries'] += session.get('session_stats', {}).get('attack_queries', 0)
        
        self.report_data['summary'] = {
            'total_sessions': len(sessions),
            'attack_sessions': len([s for s in sessions if s.get('session_stats', {}).get('attack_queries', 0) > 0]),
            'average_queries_per_session': self.report_data['metadata']['total_queries'] / len(sessions) if sessions else 0,
            'most_common_attacks': dict(attack_types.most_common(10)),
            'severity_distribution': dict(severity_counts),
            'vulnerability_distribution': dict(vulnerability_counts.most_common(10))
        }
        
        self.report_data['attack_analysis'] = {
            'attack_types': dict(attack_types),
            'severity_counts': dict(severity_counts),
            'top_attack_patterns': self._get_top_attack_patterns(sessions)
        }
        
        self.report_data['vulnerability_analysis'] = {
            'vulnerabilities_found': dict(vulnerability_counts),
            'high_risk_sessions': self._get_high_risk_sessions(sessions)
        }
        
        self.report_data['database_operations'] = {
            'databases_created': database_operations['created_databases'],
            'total_queries': database_operations['total_queries'],
            'malicious_queries': database_operations['attack_queries'],
            'common_queries': self._get_common_queries(sessions)
        }
    
    def _get_top_attack_patterns(self, sessions: List[Dict]) -> List[Dict]:
        """Get top attack patterns"""
        patterns = []
        for session in sessions:
            for analysis in session.get('attack_analysis', []):
                for match in analysis.get('pattern_matches', []):
                    patterns.append({
                        'type': match.get('type'),
                        'pattern': match.get('pattern'),
                        'severity': match.get('severity'),
                        'query': analysis.get('query', '')[:100]
                    })
        
        # Group by pattern and count
        pattern_counts = Counter(p['pattern'] for p in patterns)
        return [{'pattern': p, 'count': c} for p, c in pattern_counts.most_common(10)]
    
    def _get_high_risk_sessions(self, sessions: List[Dict]) -> List[Dict]:
        """Get high-risk sessions"""
        high_risk = []
        for session in sessions:
            risk_score = 0
            risk_factors = []
            
            # Calculate risk score
            attack_queries = session.get('session_stats', {}).get('attack_queries', 0)
            total_queries = session.get('session_stats', {}).get('total_queries', 1)
            
            if attack_queries > 0:
                risk_score += (attack_queries / total_queries) * 50
                risk_factors.append(f"{attack_queries} attack queries")
            
            if len(session.get('vulnerabilities', [])) > 0:
                risk_score += len(session.get('vulnerabilities', [])) * 20
                risk_factors.append(f"{len(session.get('vulnerabilities', []))} vulnerabilities")
            
            if len(session.get('created_databases', [])) > 0:
                risk_score += len(session.get('created_databases', [])) * 10
                risk_factors.append(f"{len(session.get('created_databases', []))} databases created")
            
            if risk_score >= 30:  # High risk threshold
                high_risk.append({
                    'session_id': session.get('session_id'),
                    'username': session.get('username'),
                    'risk_score': round(risk_score, 2),
                    'risk_factors': risk_factors,
                    'start_time': session.get('start_time')
                })
        
        return sorted(high_risk, key=lambda x: x['risk_score'], reverse=True)[:10]
    
    def _get_common_queries(self, sessions: List[Dict]) -> List[Dict]:
        """Get most common queries"""
        query_counts = Counter()
        
        for session in sessions:
            for query_info in session.get('queries', []):
                query = query_info.get('query', '').lower().strip()
                if query:
                    query_counts[query] += 1
        
        return [{'query': q, 'count': c} for q, c in query_counts.most_common(20)]
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>MySQL Honeypot Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background: #f8f9fa; border-radius: 3px; }}
        .high-risk {{ background: #ffebee; border-left: 4px solid #f44336; }}
        .medium-risk {{ background: #fff3e0; border-left: 4px solid #ff9800; }}
        .low-risk {{ background: #e8f5e8; border-left: 4px solid #4caf50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
        .query {{ font-family: monospace; background: #f5f5f5; padding: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ MySQL Honeypot Security Report</h1>
        <p>Generated: {self.report_data['metadata']['generated_at']}</p>
    </div>
    
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div class="metric">
            <strong>Sessions Analyzed:</strong> {self.report_data['metadata']['sessions_analyzed']}
        </div>
        <div class="metric">
            <strong>Total Queries:</strong> {self.report_data['metadata']['total_queries']}
        </div>
        <div class="metric">
            <strong>Unique Attackers:</strong> {self.report_data['metadata']['unique_attackers']}
        </div>
        <div class="metric">
            <strong>Attack Sessions:</strong> {self.report_data['summary'].get('attack_sessions', 0)}
        </div>
    </div>
    
    <div class="section">
        <h2>⚠️ Attack Analysis</h2>
        <h3>Most Common Attack Types</h3>
        <table>
            <tr><th>Attack Type</th><th>Count</th></tr>
        """
        
        for attack_type, count in self.report_data['summary'].get('most_common_attacks', {}).items():
            html += f"<tr><td>{attack_type}</td><td>{count}</td></tr>"
        
        html += """
        </table>
        
        <h3>Severity Distribution</h3>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
        """
        
        for severity, count in self.report_data['summary'].get('severity_distribution', {}).items():
            html += f"<tr><td>{severity}</td><td>{count}</td></tr>"
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>🔍 High-Risk Sessions</h2>
        """
        
        for session in self.report_data['vulnerability_analysis'].get('high_risk_sessions', [])[:5]:
            html += f"""
            <div class="high-risk" style="margin: 10px 0; padding: 10px;">
                <strong>Session:</strong> {session['session_id']}<br>
                <strong>User:</strong> {session['username']}<br>
                <strong>Risk Score:</strong> {session['risk_score']}<br>
                <strong>Risk Factors:</strong> {', '.join(session['risk_factors'])}<br>
                <strong>Time:</strong> {session['start_time']}
            </div>
            """
        
        html += """
    </div>
    
    <div class="section">
        <h2>💾 Database Operations</h2>
        <div class="metric">
            <strong>Databases Created:</strong> """ + str(self.report_data['database_operations'].get('databases_created', 0)) + """
        </div>
        <div class="metric">
            <strong>Total Queries:</strong> """ + str(self.report_data['database_operations'].get('total_queries', 0)) + """
        </div>
        <div class="metric">
            <strong>Malicious Queries:</strong> """ + str(self.report_data['database_operations'].get('malicious_queries', 0)) + """
        </div>
        
        <h3>Most Common Queries</h3>
        <table>
            <tr><th>Query</th><th>Count</th></tr>
        """
        
        for query_info in self.report_data['database_operations'].get('common_queries', [])[:10]:
            html += f"<tr><td class='query'>{query_info['query']}</td><td>{query_info['count']}</td></tr>"
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>🔒 Vulnerability Analysis</h2>
        <table>
            <tr><th>Vulnerability</th><th>Count</th></tr>
        """
        
        for vuln, count in self.report_data['summary'].get('vulnerability_distribution', {}).items():
            html += f"<tr><td>{vuln}</td><td>{count}</td></tr>"
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>📈 Recommendations</h2>
        <ul>
            <li><strong>Monitor SQL Injection Attempts:</strong> Implement additional monitoring for detected SQL injection patterns</li>
            <li><strong>Database Access Controls:</strong> Review database creation and access patterns</li>
            <li><strong>Vulnerability Patching:</strong> Address identified vulnerability exploitation attempts</li>
            <li><strong>User Account Security:</strong> Monitor suspicious authentication patterns</li>
            <li><strong>Query Analysis:</strong> Implement real-time query analysis for threat detection</li>
        </ul>
    </div>
    
</body>
</html>
        """
        
        return html

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python report_generator.py <sessions_directory>")
        sys.exit(1)
    
    sessions_dir = sys.argv[1]
    generator = MySQLHoneypotReportGenerator(sessions_dir)
    
    print("Generating MySQL honeypot security report...")
    result = generator.generate_comprehensive_report()
    
    if "error" in result:
        print(f"Error: {result['error']}")
        sys.exit(1)
    
    print("Report generated successfully!")
    print(f"JSON Report: {result.get('json', 'Not generated')}")
    print(f"HTML Report: {result.get('html', 'Not generated')}")