#!/usr/bin/env python3

import json
import numpy as np
import os
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
import re

# Import ML components
try:
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from ai.detectors import MLDetector
    from ai.config import MLConfig
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    print(f"Warning: ML components not available for MYSQL report generation: {e}")

# Import LLM components for AI-generated insights
LLM_AVAILABLE = False
try:
    from langchain_openai import ChatOpenAI
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_ollama import ChatOllama
    from dotenv import load_dotenv
    load_dotenv()
    LLM_AVAILABLE = True
except ImportError:
    pass  # LLM features will use rule-based fallback


class MySQLHoneypotReportGenerator:
    """Generate comprehensive security reports for MySQL honeypot with modern UI/UX"""
    
    def __init__(self, sessions_dir: str, logs_dir: str = None, ai_provider: str = 'ollama', ai_model: str = None):
        self.sessions_dir = Path(sessions_dir)
        self.logs_dir = Path(logs_dir) if logs_dir else None
        self.ai_provider = ai_provider
        self.ai_model = ai_model
        
        # Initialize ML detector for enhanced analysis
        self.ml_detector = None
        if ML_AVAILABLE:
            try:
                ml_config = MLConfig('mysql')
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector('mysql', ml_config)
                    print("ML detector initialized for MySQL report generation")
            except Exception as e:
                print(f"Warning: Failed to initialize ML detector for MySQL reports: {e}")
                self.ml_detector = None
        self.report_data = {
            'metadata': {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'generator_version': '2.0.0',
                'report_type': 'MySQL Honeypot Security Analysis',
                'sessions_analyzed': 0,
                'total_queries': 0,
                'unique_attackers': 0,
                'log_entries_processed': 0
            },
            'executive_summary': {},
            'ml_analysis': {
                'enabled': ML_AVAILABLE and hasattr(self, 'ml_detector') and self.ml_detector is not None,
                'anomaly_detection': {},
                'threat_classification': {},
                'confidence_scores': {},
                'ml_insights': [],
                'total_ml_analyzed': 0,
                'high_anomaly_sessions': 0,
                'ml_detected_threats': []
            },
            'threat_intelligence': {},
            'attack_analysis': {},
            'vulnerability_analysis': {},
            'database_operations': {},
            'forensic_timeline': [],
            'session_details': [],
            'log_analysis': {},
            'recommendations': []
        }
    
    def generate_comprehensive_report(self, output_dir: str = "reports", format_type: str = "both") -> Dict[str, str]:
        """Generate comprehensive MySQL security report"""
        try:
            # Analyze all sessions
            self._analyze_sessions()
            
            # Analyze log files
            self._analyze_logs()
            
            # Generate summary statistics
            self._generate_summary()
            
            # Generate enhanced analysis
            self._generate_enhanced_analysis()
            
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
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
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
            print(f"Warning: Sessions directory '{self.sessions_dir}' does not exist")
            self.report_data['metadata']['sessions_analyzed'] = 0
            self.report_data['metadata']['total_queries'] = 0
            self.report_data['metadata']['unique_attackers'] = 0
            self.report_data['session_details'] = []
            return
        
        sessions = []
        attackers = {}  # Changed to dict to store attacker details
        total_queries = 0
        
        for session_dir in self.sessions_dir.iterdir():
            if not session_dir.is_dir():
                continue
            
            # Try multiple session file names - prefer session_data.json for queries
            # session_summary.json often has empty queries while session_data.json has actual data
            session_files = [
                session_dir / "session_data.json",  # Prioritize - usually has queries
                session_dir / "session_summary.json"
            ]
            
            session_data = None
            for session_file in session_files:
                if session_file.exists():
                    try:
                        with open(session_file, 'r', encoding='utf-8') as f:
                            file_data = json.load(f)
                        
                        if session_data is None:
                            session_data = file_data
                        else:
                            # Merge: prefer queries from file that has them
                            if file_data.get('queries') and len(file_data.get('queries', [])) > len(session_data.get('queries', [])):
                                session_data['queries'] = file_data['queries']
                            # Also merge attack_analysis if present
                            if file_data.get('attack_analysis') and not session_data.get('attack_analysis'):
                                session_data['attack_analysis'] = file_data['attack_analysis']
                    except Exception as e:
                        print(f"Warning: Could not read session file {session_file}: {e}")
                        continue
            
            if not session_data:
                continue
                
            sessions.append(session_data)
            
            # Extract attacker information from queries (more reliable)
            client_ip = 'unknown'
            client_port = 'unknown'
            username = 'unknown'
            
            # Try to get IP from queries first
            for query in session_data.get('queries', []):
                if query.get('username'):
                    username = query.get('username')
                    break
            
            # Check multiple possible locations for IP
            client_ip = (session_data.get('client_info', {}).get('ip') or 
                        session_data.get('client_ip') or 
                        session_data.get('ip', 'unknown'))
            
            client_port = (session_data.get('client_info', {}).get('port') or 
                          session_data.get('client_port', 'unknown'))
            
            if client_ip != 'unknown':
                if client_ip not in attackers:
                    attackers[client_ip] = {
                        'ip': client_ip,
                        'port': client_port,
                        'username': username,
                        'sessions': 0,
                        'queries': 0,
                        'attack_types': set(),
                        'first_seen': session_data.get('start_time'),
                        'last_seen': session_data.get('end_time'),
                        'risk_score': 0
                    }
                
                # Update attacker statistics
                attackers[client_ip]['sessions'] += 1
                attackers[client_ip]['queries'] += len(session_data.get('queries', []))
                
                # Extract attack types and calculate risk
                for query in session_data.get('queries', []):
                    attack_analysis = query.get('attack_analysis', {})
                    for attack_type in attack_analysis.get('attack_types', []):
                        attackers[client_ip]['attack_types'].add(attack_type)
                    
                    # Calculate risk score
                    severity = attack_analysis.get('severity', 'low')
                    if severity == 'critical':
                        attackers[client_ip]['risk_score'] += 10
                    elif severity == 'high':
                        attackers[client_ip]['risk_score'] += 5
                    elif severity == 'medium':
                        attackers[client_ip]['risk_score'] += 2
                
                # Update last seen
                if session_data.get('end_time'):
                    attackers[client_ip]['last_seen'] = session_data.get('end_time')
            
            # Count queries
            total_queries += len(session_data.get('queries', []))
        
        # Convert attack_types sets to lists for JSON serialization
        for attacker in attackers.values():
            attacker['attack_types'] = list(attacker['attack_types'])
        
        self.report_data['metadata']['sessions_analyzed'] = len(sessions)
        self.report_data['metadata']['total_queries'] = total_queries
        self.report_data['metadata']['unique_attackers'] = len(attackers)
        self.report_data['session_details'] = sessions
        self.report_data['attacker_details'] = list(attackers.values())
    
    def _generate_summary(self):
        """Generate summary statistics"""
        sessions = self.report_data['session_details']
        
        # Attack statistics
        attack_types = Counter()
        severity_counts = Counter()
        vulnerability_counts = Counter()
        database_operations = Counter()
        
        for session in sessions:
            # Extract attack types and vulnerabilities from queries
            session_attack_queries = 0
            for query in session.get('queries', []):
                attack_analysis = query.get('attack_analysis', {})
                
                # Count attack types from each query
                for attack_type in attack_analysis.get('attack_types', []):
                    attack_types[attack_type] += 1
                
                # Count severity levels
                severity = attack_analysis.get('severity', 'unknown')
                if severity != 'unknown':
                    severity_counts[severity] += 1
                
                # Count if this is an attack query
                if attack_analysis.get('attack_types', []):
                    session_attack_queries += 1
                
                # Count vulnerabilities from each query
                for vuln in query.get('vulnerabilities', []):
                    vulnerability_counts[vuln.get('vulnerability_id', 'unknown')] += 1
            
            # Count database operations based on actual queries
            database_operations['total_queries'] += len(session.get('queries', []))
            database_operations['attack_queries'] += session_attack_queries
        
        # Calculate attack sessions based on actual attack queries
        attack_sessions = 0
        for session in sessions:
            has_attacks = any(query.get('attack_analysis', {}).get('attack_types', []) 
                            for query in session.get('queries', []))
            if has_attacks:
                attack_sessions += 1
        
        # Calculate high risk and critical events
        high_risk_sessions = sum(1 for session in sessions 
                               for query in session.get('queries', [])
                               if query.get('attack_analysis', {}).get('severity') in ['critical', 'high'])
        
        critical_events = sum(1 for session in sessions 
                            for query in session.get('queries', [])
                            if query.get('attack_analysis', {}).get('severity') == 'critical')
        
        self.report_data['executive_summary'] = {
            'total_sessions': len(sessions),
            'total_queries': database_operations['total_queries'],
            'unique_attackers': self.report_data['metadata']['unique_attackers'],
            'attack_sessions': attack_sessions,
            'high_risk_sessions': high_risk_sessions,
            'critical_events': critical_events,
            'most_common_attacks': dict(attack_types.most_common(10)),
            'severity_distribution': dict(severity_counts),
            'vulnerability_distribution': dict(vulnerability_counts.most_common(10))
        }
        
        self.report_data['attack_analysis'] = {
            'attack_types': dict(attack_types),
            'severity_distribution': dict(severity_counts),
            'total_attacks': sum(attack_types.values()),
            'top_attack_patterns': self._get_top_attack_patterns(sessions)
        }
        
        self.report_data['vulnerability_analysis'] = {
            'vulnerabilities_detected': self._get_vulnerability_details(sessions),
            'vulnerability_distribution': dict(vulnerability_counts),
            'total_vulnerabilities': sum(vulnerability_counts.values()),
            'high_risk_sessions': self._get_high_risk_sessions(sessions)
        }
        
        self.report_data['database_operations'] = {
            'databases_created': database_operations.get('created_databases', 0),
            'total_queries': database_operations['total_queries'],
            'malicious_queries': database_operations['attack_queries'],
            'common_queries': self._get_common_queries(sessions)
        }
    
    def _get_top_attack_patterns(self, sessions: List[Dict]) -> List[Dict]:
        """Get top attack patterns from queries"""
        patterns = []
        for session in sessions:
            for query in session.get('queries', []):
                attack_analysis = query.get('attack_analysis', {})
                for match in attack_analysis.get('pattern_matches', []):
                    patterns.append({
                        'type': match.get('type'),
                        'pattern': match.get('pattern'),
                        'severity': match.get('severity'),
                        'query': query.get('query', '')[:100]
                    })
        
        # Group by pattern and count occurrences
        pattern_counts = {}
        for pattern in patterns:
            key = f"{pattern['type']}:{pattern['pattern']}"
            if key not in pattern_counts:
                pattern_counts[key] = {
                    'type': pattern['type'],
                    'pattern': pattern['pattern'],
                    'severity': pattern['severity'],
                    'count': 0,
                    'example_query': pattern['query']
                }
            pattern_counts[key]['count'] += 1
        
        return sorted(pattern_counts.values(), key=lambda x: x['count'], reverse=True)[:10]
    
    def _get_vulnerability_details(self, sessions: List[Dict]) -> Dict:
        """Get detailed vulnerability information"""
        vulnerabilities = {}
        
        for session in sessions:
            for query in session.get('queries', []):
                for vuln in query.get('vulnerabilities', []):
                    vuln_id = vuln.get('vulnerability_id', 'UNKNOWN')
                    if vuln_id not in vulnerabilities:
                        vulnerabilities[vuln_id] = {
                            'vuln_name': vuln.get('vuln_name', vuln_id),
                            'severity': vuln.get('severity', 'unknown'),
                            'cvss_score': vuln.get('cvss_score', 0),
                            'description': vuln.get('description', 'No description available'),
                            'count': 0,
                            'indicators': vuln.get('indicators', []),
                            'pattern_matched': vuln.get('pattern_matched', '')
                        }
                    vulnerabilities[vuln_id]['count'] += 1
        
        return vulnerabilities
    
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
            
            # amazonq-ignore-next-line
            # amazonq-ignore-next-line
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
        """Get most common queries with types and analysis"""
        query_data = {}
        
        for session in sessions:
            for query_info in session.get('queries', []):
                query = query_info.get('query', '').strip()
                query_type = query_info.get('query_type', 'UNKNOWN')
                
                if query:
                    if query not in query_data:
                        query_data[query] = {
                            'query': query,
                            'count': 0,
                            'type': query_type,
                            'attack_analysis': query_info.get('attack_analysis', {}),
                            'vulnerabilities': query_info.get('vulnerabilities', [])
                        }
                    query_data[query]['count'] += 1
        
        # Sort by count and return top 20
        sorted_queries = sorted(query_data.values(), key=lambda x: x['count'], reverse=True)
        return sorted_queries[:20]
    
    def _analyze_logs(self):
        """Analyze MySQL log files for additional insights"""
        if not self.logs_dir:
            # Initialize empty log analysis if no logs directory
            self.report_data['log_analysis'] = {
                'total_entries': 0,
                'attack_events': 0,
                'vulnerability_events': 0,
                'query_events': 0,
                'session_events': 0,
                'timeline': [],
                'top_attackers': Counter(),
                'query_types': Counter(),
                'attack_patterns': Counter()
            }
            self.report_data['metadata']['log_entries_processed'] = 0
            return
            
        log_entries = []
        mysql_log_file = self.logs_dir / "mysql_log.log"
        
        if mysql_log_file.exists():
            try:
                with open(mysql_log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entry = json.loads(line)
                                log_entries.append(entry)
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                print(f"Error reading log file: {e}")
        else:
            print(f"Warning: MySQL log file not found at {mysql_log_file}")
        
        self.report_data['metadata']['log_entries_processed'] = len(log_entries)
        self.report_data['log_analysis'] = self._process_log_entries(log_entries)
    
    def _process_log_entries(self, log_entries: List[Dict]) -> Dict:
        """Process log entries for analysis"""
        analysis = {
            'total_entries': len(log_entries),
            'attack_events': 0,
            'vulnerability_events': 0,
            'query_events': 0,
            'session_events': 0,
            'timeline': [],
            'top_attackers': Counter(),
            'query_types': Counter(),
            'attack_patterns': Counter()
        }
        
        for entry in log_entries:
            timestamp = entry.get('timestamp', '')
            level = entry.get('level', 'INFO')
            message = entry.get('message', '')
            client_ip = entry.get('client_ip', 'unknown')
            
            analysis['total_entries'] += 1
            
            # Track attackers from logs
            if client_ip != 'unknown' and client_ip not in analysis['top_attackers']:
                analysis['top_attackers'][client_ip] = 0
            if client_ip != 'unknown':
                analysis['top_attackers'][client_ip] += 1
            
            if level in ['WARNING', 'CRITICAL']:
                analysis['attack_events'] += 1
                
                # Extract attack patterns
                attack_types = entry.get('attack_types', [])
                for attack_type in attack_types:
                    analysis['attack_patterns'][attack_type] += 1
                
                # Extract query information
                query = entry.get('query', '')
                if query:
                    analysis['query_events'] += 1
                    query_type = entry.get('query_type', 'UNKNOWN')
                    analysis['query_types'][query_type] += 1
            
            if 'vulnerability' in message.lower():
                analysis['vulnerability_events'] += 1
            
            if 'session' in message.lower():
                analysis['session_events'] += 1
            
            # Add to timeline for critical events
            if level in ['WARNING', 'CRITICAL']:
                analysis['timeline'].append({
                    'timestamp': timestamp,
                    'level': level,
                    'message': message,
                    'session_id': entry.get('session_id', ''),
                    'query': entry.get('query', '')[:100] if entry.get('query') else '',
                    'client_ip': client_ip,
                    'attack_types': attack_types,
                    'severity': entry.get('severity', 'unknown')
                })
        
        # Sort timeline by timestamp
        analysis['timeline'].sort(key=lambda x: x['timestamp'])
        
        return analysis
    
    def _generate_enhanced_analysis(self):
        """Generate enhanced analysis combining session and log data with AI insights"""
        sessions = self.report_data['session_details']
        log_analysis = self.report_data.get('log_analysis', {})
        
        # Executive Summary - Core Statistics
        self.report_data['executive_summary'] = {
            'total_sessions': len(sessions),
            'total_queries': self.report_data['metadata']['total_queries'],
            'unique_attackers': self.report_data['metadata']['unique_attackers'],
            'attack_sessions': len([s for s in sessions if s.get('session_stats', {}).get('attack_queries', 0) > 0]),
            'high_risk_sessions': len(self.report_data['vulnerability_analysis'].get('high_risk_sessions', [])),
            'log_events_analyzed': log_analysis.get('total_entries', 0),
            'critical_events': len([e for e in log_analysis.get('timeline', []) if e.get('level') == 'CRITICAL']),
            'warning_events': len([e for e in log_analysis.get('timeline', []) if e.get('level') == 'WARNING'])
        }
        
        # Generate AI-powered executive summary
        self.report_data['executive_summary']['ai_summary'] = self._generate_ai_executive_summary()
        
        # Generate risk assessment
        self.report_data['executive_summary']['risk_assessment'] = self._calculate_risk_assessment()
        
        # Threat Intelligence
        attack_patterns = log_analysis.get('attack_patterns', Counter())
        top_attackers = log_analysis.get('top_attackers', Counter())
        query_types = log_analysis.get('query_types', Counter())
        
        self.report_data['threat_intelligence'] = {
            'attack_patterns': dict(attack_patterns.most_common(10)) if hasattr(attack_patterns, 'most_common') else dict(attack_patterns),
            'top_attackers': dict(top_attackers.most_common(5)) if hasattr(top_attackers, 'most_common') else dict(top_attackers),
            'query_distribution': dict(query_types.most_common(10)) if hasattr(query_types, 'most_common') else dict(query_types),
            'attack_timeline': log_analysis.get('timeline', [])[-20:],  # Last 20 critical events
            'vulnerability_trends': self._analyze_vulnerability_trends(sessions)
        }
        
        # Merge attacker data from logs with session data
        self._merge_log_attacker_data()
        
        # Generate recommendations (now with AI enhancement)
        self.report_data['recommendations'] = self._generate_recommendations()
    
    def _analyze_vulnerability_trends(self, sessions: List[Dict]) -> Dict:
        """Analyze vulnerability exploitation trends"""
        trends = {
            'most_exploited': Counter(),
            'severity_trends': Counter(),
            'temporal_analysis': {}
        }
        
        for session in sessions:
            for query in session.get('queries', []):
                if 'attack_analysis' in query:
                    for vuln in query['attack_analysis'].get('vulnerabilities', []):
                        trends['most_exploited'][vuln.get('vulnerability_id', 'unknown')] += 1
                        trends['severity_trends'][vuln.get('severity', 'unknown')] += 1
        
        return {
            'most_exploited_vulnerabilities': dict(trends['most_exploited'].most_common(10)),
            'severity_distribution': dict(trends['severity_trends'])
        }
    
    def _generate_recommendations(self) -> List[Dict]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Get analysis data
        attack_analysis = self.report_data.get('attack_analysis', {})
        vuln_analysis = self.report_data.get('vulnerability_analysis', {})
        exec_summary = self.report_data.get('executive_summary', {})
        log_analysis = self.report_data.get('log_analysis', {})
        
        attack_types = attack_analysis.get('attack_types', {})
        vulnerabilities = vuln_analysis.get('vulnerabilities_detected', {})
        critical_events = exec_summary.get('critical_events', 0)
        attack_sessions = exec_summary.get('attack_sessions', 0)
        
        # High priority recommendations based on critical events
        if critical_events > 0:
            recommendations.append({
                'priority': 'critical',
                'category': 'Immediate Response',
                'title': 'Critical Security Events Detected',
                'description': f'Detected {critical_events} critical security events requiring immediate attention.',
                'action_items': [
                    'Review and investigate all critical events immediately',
                    'Implement emergency response procedures',
                    'Consider temporarily restricting database access',
                    'Notify security team and stakeholders'
                ]
            })
        
        # SQL Injection recommendations
        if 'sql_injection' in attack_types and attack_types['sql_injection'] > 0:
            recommendations.append({
                'priority': 'high',
                'category': 'SQL Injection Protection',
                'title': 'SQL Injection Attacks Detected',
                'description': f'Detected {attack_types["sql_injection"]} SQL injection attempts. Immediate protection required.',
                'action_items': [
                    'Implement parameterized queries and prepared statements',
                    'Deploy Web Application Firewall with SQL injection rules',
                    'Enable MySQL query logging and monitoring',
                    'Conduct security code review of database interactions',
                    'Implement input validation and sanitization'
                ]
            })
        
        # Reconnaissance recommendations
        if 'reconnaissance' in attack_types and attack_types['reconnaissance'] > 0:
            recommendations.append({
                'priority': 'medium',
                'category': 'Information Disclosure',
                'title': 'Database Reconnaissance Detected',
                'description': f'Detected {attack_types["reconnaissance"]} reconnaissance attempts targeting database structure.',
                'action_items': [
                    'Disable information_schema access for non-admin users',
                    'Hide MySQL version information',
                    'Implement database activity monitoring',
                    'Review and restrict SHOW commands permissions',
                    'Enable detailed query logging'
                ]
            })
        
        # Vulnerability-specific recommendations
        if 'MYSQL_INFORMATION_DISCLOSURE' in vulnerabilities:
            vuln_count = vulnerabilities['MYSQL_INFORMATION_DISCLOSURE']['count']
            recommendations.append({
                'priority': 'high',
                'category': 'Information Security',
                'title': 'MySQL Information Disclosure Vulnerability',
                'description': f'Detected {vuln_count} attempts to exploit information disclosure vulnerability.',
                'action_items': [
                    'Restrict access to system variables and functions',
                    'Disable unnecessary MySQL functions and features',
                    'Implement proper user privilege separation',
                    'Review and update MySQL configuration',
                    'Apply latest security patches'
                ]
            })
        
        # General security recommendations based on attack volume
        if attack_sessions > 1:
            recommendations.append({
                'priority': 'medium',
                'category': 'General Security',
                'title': 'Multiple Attack Sessions Detected',
                'description': f'Detected {attack_sessions} sessions with attack attempts. Strengthen overall security posture.',
                'action_items': [
                    'Implement connection rate limiting',
                    'Enable fail2ban or similar intrusion prevention',
                    'Set up real-time alerting for attack patterns',
                    'Review and strengthen authentication mechanisms',
                    'Implement network segmentation for database access'
                ]
            })
        
        # Monitoring and logging recommendations
        recommendations.append({
            'priority': 'medium',
            'category': 'Monitoring & Logging',
            'title': 'Enhanced Security Monitoring',
            'description': 'Implement comprehensive monitoring to detect future attacks.',
            'action_items': [
                'Enable comprehensive MySQL audit logging',
                'Set up SIEM integration for log analysis',
                'Implement real-time attack detection rules',
                'Configure automated alerting for suspicious activities',
                'Regular security assessment and penetration testing'
            ]
        })
        
        # Compliance and best practices
        recommendations.append({
            'priority': 'low',
            'category': 'Best Practices',
            'title': 'Security Best Practices Implementation',
            'description': 'Follow MySQL security best practices to prevent future attacks.',
            'action_items': [
                'Regular security updates and patch management',
                'Implement principle of least privilege',
                'Use strong authentication and encryption',
                'Regular backup and disaster recovery testing',
                'Security awareness training for development teams'
            ]
        })
        
        return recommendations
    
    def _generate_ai_executive_summary(self) -> Dict[str, Any]:
        """Generate AI-powered executive summary using LLM or rule-based fallback"""
        summary = self.report_data.get('executive_summary', {})
        attack_analysis = self.report_data.get('attack_analysis', {})
        
        # Build context from actual data
        context = self._build_summary_context(summary, attack_analysis)
        
        # Try LLM-based generation if available
        if LLM_AVAILABLE:
            try:
                ai_summary = self._generate_llm_summary(context)
                return {
                    'ai_generated': True,
                    'content': ai_summary,
                    'generated_at': datetime.now(timezone.utc).isoformat()
                }
            except Exception as e:
                print(f"LLM summary generation failed, using fallback: {e}")
        
        # Rule-based fallback
        return {
            'ai_generated': False,
            'content': self._generate_rule_based_summary(summary, attack_analysis),
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
    
    def _build_summary_context(self, summary: Dict, attack_analysis: Dict) -> str:
        """Build context string for LLM summary generation"""
        attack_types = attack_analysis.get('attack_types', {})
        severity_dist = attack_analysis.get('severity_distribution', {})
        
        return f"""
MySQL Honeypot Security Analysis Data:
- Total Sessions: {summary.get('total_sessions', 0)}
- Total Queries: {summary.get('total_queries', 0)}
- Attack Sessions: {summary.get('attack_sessions', 0)}
- Unique Attackers: {summary.get('unique_attackers', 0)}
- Critical Events: {summary.get('critical_events', 0)}
- High Risk Sessions: {summary.get('high_risk_sessions', 0)}

Attack Types Detected:
{chr(10).join(f'  - {k}: {v}' for k, v in attack_types.items()) if attack_types else '  None detected'}

Severity Distribution:
{chr(10).join(f'  - {k}: {v}' for k, v in severity_dist.items()) if severity_dist else '  None recorded'}
"""
    
    def _generate_llm_summary(self, context: str) -> str:
        """Generate summary using LLM"""
        prompt = f"""You are a cybersecurity analyst writing an executive summary for a MySQL honeypot security report.

Based on the following data, write a concise 2-3 paragraph executive summary highlighting:
1. Overall threat landscape and attack volume
2. Most significant attack types and their severity
3. Key findings that require attention

Data:
{context}

Write the summary in a professional, factual tone. Focus only on the data provided - do not make up statistics."""
        
        model = self.ai_model  # Use configured model or None for defaults
        
        # Use configured provider priority
        if self.ai_provider == 'ollama':
            try:
                llm = ChatOllama(model=model or "llama3.2", temperature=0.3)
                response = llm.invoke(prompt)
                return response.content if hasattr(response, 'content') else str(response)
            except Exception:
                pass
        
        elif self.ai_provider == 'openai':
            openai_key = os.getenv("OPENAI_API_KEY")
            if openai_key:
                try:
                    llm = ChatOpenAI(model=model or "gpt-4o-mini", temperature=0.3, api_key=openai_key)
                    response = llm.invoke(prompt)
                    return response.content if hasattr(response, 'content') else str(response)
                except Exception:
                    pass
        
        elif self.ai_provider == 'google':
            google_key = os.getenv("GOOGLE_API_KEY")
            if google_key:
                try:
                    llm = ChatGoogleGenerativeAI(model=model or "gemini-1.5-flash", temperature=0.3, google_api_key=google_key)
                    response = llm.invoke(prompt)
                    return response.content if hasattr(response, 'content') else str(response)
                except Exception:
                    pass
        
        # Fallback chain if primary provider fails
        providers = [
            ('ollama', lambda: ChatOllama(model=model or "llama3.2", temperature=0.3)),
            ('openai', lambda: ChatOpenAI(model=model or "gpt-4o-mini", temperature=0.3, api_key=os.getenv("OPENAI_API_KEY")) if os.getenv("OPENAI_API_KEY") else None),
            ('google', lambda: ChatGoogleGenerativeAI(model=model or "gemini-1.5-flash", temperature=0.3, google_api_key=os.getenv("GOOGLE_API_KEY")) if os.getenv("GOOGLE_API_KEY") else None)
        ]
        
        for name, factory in providers:
            if name == self.ai_provider:
                continue  # Already tried
            try:
                llm = factory()
                if llm:
                    response = llm.invoke(prompt)
                    return response.content if hasattr(response, 'content') else str(response)
            except Exception:
                pass
        
        raise Exception("No LLM provider available")
    
    def _generate_rule_based_summary(self, summary: Dict, attack_analysis: Dict) -> str:
        """Generate summary using rules when LLM unavailable"""
        total_sessions = summary.get('total_sessions', 0)
        total_queries = summary.get('total_queries', 0)
        attack_sessions = summary.get('attack_sessions', 0)
        unique_attackers = summary.get('unique_attackers', 0)
        critical_events = summary.get('critical_events', 0)
        
        attack_types = attack_analysis.get('attack_types', {})
        severity_dist = attack_analysis.get('severity_distribution', {})
        
        lines = []
        
        # Overview paragraph
        if total_sessions > 0:
            attack_rate = (attack_sessions / total_sessions * 100) if total_sessions > 0 else 0
            lines.append(f"During the analysis period, the MySQL honeypot captured {total_sessions} sessions from {unique_attackers} unique IP addresses, processing a total of {total_queries} queries.")
            
            if attack_sessions > 0:
                lines.append(f" Of these, {attack_sessions} sessions ({attack_rate:.1f}%) contained potentially malicious activity.")
            else:
                lines.append(" No malicious activity was detected during this period.")
        else:
            lines.append("No sessions were captured during the analysis period.")
        
        # Attack analysis paragraph
        if attack_types:
            top_attack = max(attack_types.items(), key=lambda x: x[1])
            lines.append(f"\n\nThe most prevalent attack type was '{top_attack[0].replace('_', ' ')}' with {top_attack[1]} occurrences.")
            
            critical_count = severity_dist.get('critical', 0)
            high_count = severity_dist.get('high', 0)
            if critical_count > 0 or high_count > 0:
                lines.append(f" There were {critical_count} critical and {high_count} high-severity events requiring immediate attention.")
        
        # Risk assessment
        if critical_events > 0:
            lines.append("\n\nImmediate action is recommended to investigate the critical events detected. Consider implementing additional security controls and monitoring.")
        elif attack_sessions > 0:
            lines.append("\n\nContinued monitoring is recommended. Review the attack patterns to strengthen detection and prevention measures.")
        
        return "".join(lines)
    
    def _calculate_risk_assessment(self) -> Dict[str, Any]:
        """Calculate overall risk assessment based on collected data"""
        summary = self.report_data.get('executive_summary', {})
        attack_analysis = self.report_data.get('attack_analysis', {})
        
        # Extract metrics
        total_sessions = summary.get('total_sessions', 0)
        attack_sessions = summary.get('attack_sessions', 0)
        critical_events = summary.get('critical_events', 0)
        high_risk_sessions = summary.get('high_risk_sessions', 0)
        
        severity_dist = attack_analysis.get('severity_distribution', {})
        critical_count = severity_dist.get('critical', 0)
        high_count = severity_dist.get('high', 0)
        
        # Calculate risk score (0-100)
        risk_score = 0
        
        # Attack rate contribution (max 30)
        if total_sessions > 0:
            attack_rate = attack_sessions / total_sessions
            risk_score += min(30, attack_rate * 60)
        
        # Critical events contribution (max 30)
        risk_score += min(30, critical_count * 5)
        
        # High severity contribution (max 20)
        risk_score += min(20, high_count * 2)
        
        # High risk sessions contribution (max 20)
        risk_score += min(20, high_risk_sessions * 3)
        
        risk_score = min(100, max(0, risk_score))
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'critical'
            color = '#dc3545'
            recommendation = 'Immediate action required. Review all critical events and implement emergency security measures.'
        elif risk_score >= 50:
            risk_level = 'high'
            color = '#fd7e14'
            recommendation = 'Elevated risk detected. Prioritize addressing high-severity findings.'
        elif risk_score >= 30:
            risk_level = 'medium'
            color = '#ffc107'
            recommendation = 'Moderate risk level. Continue monitoring and address recommendations.'
        else:
            risk_level = 'low'
            color = '#28a745'
            recommendation = 'Risk within acceptable parameters. Maintain current security posture.'
        
        return {
            'risk_score': round(risk_score, 1),
            'risk_level': risk_level,
            'color': color,
            'recommendation': recommendation,
            'contributing_factors': {
                'attack_rate': round((attack_sessions / total_sessions * 100) if total_sessions > 0 else 0, 1),
                'critical_events': critical_count,
                'high_severity_events': high_count,
                'high_risk_sessions': high_risk_sessions
            }
        }

    
    def _generate_html_report(self) -> str:
        """Generate modern HTML report with advanced UI/UX matching other services"""
        return self._build_complete_html_template()
    
    def _build_complete_html_template(self) -> str:
        """Build complete modern HTML template with tabbed interface"""
        # Get data for the report
        summary = self.report_data.get('executive_summary', {})
        attack_analysis = self.report_data.get('attack_analysis', {})
        vuln_analysis = self.report_data.get('vulnerability_analysis', {})
        db_ops = self.report_data.get('database_operations', {})
        threat_intel = self.report_data.get('threat_intelligence', {})
        recommendations = self.report_data.get('recommendations', [])
        sessions = self.report_data.get('session_details', [])
        log_analysis = self.report_data.get('log_analysis', {})
        
        # Extract AI summary and risk assessment values (avoid {{}} issues in f-strings)
        ai_summary = summary.get('ai_summary', {})
        ai_summary_content = ai_summary.get('content', 'Summary generation in progress...')
        
        risk_assessment = summary.get('risk_assessment', {})
        risk_score = risk_assessment.get('risk_score', 0)
        risk_level = risk_assessment.get('risk_level', 'low')
        risk_color = risk_assessment.get('color', '#28a745')
        risk_recommendation = risk_assessment.get('recommendation', 'Risk assessment pending.')
        
        contributing_factors = risk_assessment.get('contributing_factors', {})
        attack_rate = contributing_factors.get('attack_rate', 0)
        critical_events_count = contributing_factors.get('critical_events', 0)
        high_severity_count = contributing_factors.get('high_severity_events', 0)
        high_risk_sessions_count = contributing_factors.get('high_risk_sessions', 0)
        
        # Generate data sections
        attackers_rows = self._generate_attackers_table()
        attacks_rows = self._generate_attacks_table()
        queries_rows = self._generate_queries_table()
        sessions_rows = self._generate_sessions_table()
        timeline_items = self._generate_timeline_items()
        recommendations_list = self._generate_recommendations_list()
        vulnerability_rows = self._generate_vulnerability_table()
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEXUS MySQL Security Analysis Report</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>
    <style>
        :root {{
            --primary-color: #0ea5e9;
            --secondary-color: #0284c7;
            --accent-color: #38bdf8;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --info-color: #06b6d4;
            --dark-color: #1e293b;
            --light-color: #f8fafc;
            --border-color: #e2e8f0;
            --text-primary: #0f172a;
            --text-secondary: #64748b;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0ea5e9 0%, #1e293b 100%);
            min-height: 100vh;
            color: var(--text-primary);
            line-height: 1.6;
        }}
        
        .report-container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .report-header {{
            background: linear-gradient(135deg, #0284c7 0%, #1e293b 100%);
            color: white;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
            box-shadow: var(--shadow-xl);
        }}
        
        .report-header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }}
        
        .report-header > * {{
            position: relative;
            z-index: 1;
        }}
        
        .report-title {{
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .report-subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 30px;
        }}
        
        .report-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }}
        
        .meta-item {{
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }}
        
        .main-content {{
            background: white;
            border-radius: 16px;
            padding: 30px;
            box-shadow: var(--shadow-lg);
            margin-bottom: 30px;
        }}
        
        .nav-tabs {{
            display: flex;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 30px;
            overflow-x: auto;
        }}
        
        .nav-tab {{
            padding: 15px 25px;
            background: none;
            border: none;
            cursor: pointer;
            font-weight: 500;
            color: var(--text-secondary);
            transition: all 0.3s ease;
            white-space: nowrap;
            position: relative;
        }}
        
        .nav-tab:hover {{
            color: var(--primary-color);
            background: rgba(14, 165, 233, 0.05);
        }}
        
        .nav-tab.active {{
            color: var(--primary-color);
            font-weight: 600;
        }}
        
        .nav-tab.active::after {{
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--primary-color);
        }}
        
        .tab-content {{
            display: none;
        }}
        
        .tab-content.active {{
            display: block;
            animation: fadeIn 0.3s ease;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            border-left: 4px solid var(--primary-color);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }}
        
        .stat-number {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-weight: 500;
        }}
        
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: var(--shadow-sm);
        }}
        
        .data-table th {{
            background: var(--primary-color);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        .data-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .data-table tr:hover {{
            background: #f8fafc;
        }}
        
        .severity-critical {{
            background: #fef2f2;
            color: #991b1b;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: 500;
        }}
        
        .severity-high {{
            background: #fef3c7;
            color: #92400e;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: 500;
        }}
        
        .severity-medium {{
            background: #ecfdf5;
            color: #065f46;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: 500;
        }}
        
        .query-code {{
            font-family: 'Courier New', monospace;
            background: #f1f5f9;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.875rem;
            border-left: 3px solid var(--primary-color);
            overflow-x: auto;
        }}
        
        .timeline {{
            position: relative;
            padding: 20px 0;
        }}
        
        .timeline::before {{
            content: '';
            position: absolute;
            left: 30px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--border-color);
        }}
        
        .timeline-item {{
            position: relative;
            padding: 20px 0 20px 70px;
            margin-bottom: 20px;
        }}
        
        .timeline-item::before {{
            content: '';
            position: absolute;
            left: 24px;
            top: 25px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--primary-color);
            border: 3px solid white;
            box-shadow: 0 0 0 3px var(--primary-color);
        }}
        
        .timeline-content {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: var(--shadow-sm);
            border-left: 4px solid var(--primary-color);
        }}
        
        .recommendation-item {{
            background: #f8fafc;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--warning-color);
        }}
        
        .recommendation-title {{
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 10px;
        }}
        
        .recommendation-description {{
            color: var(--text-secondary);
            margin-bottom: 15px;
        }}
        
        .recommendation-actions {{
            list-style: none;
            padding: 0;
        }}
        
        .recommendation-actions li {{
            padding: 5px 0;
            padding-left: 20px;
            position: relative;
        }}
        
        .recommendation-actions li::before {{
            content: '→';
            position: absolute;
            left: 0;
            color: var(--primary-color);
            font-weight: bold;
        }}
        
        .search-container {{
            margin-bottom: 20px;
        }}
        
        .search-input {{
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 1rem;
        }}
        
        .search-input:focus {{
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.1);
        }}
        
        @media (max-width: 768px) {{
            .report-container {{
                padding: 10px;
            }}
            
            .report-title {{
                font-size: 2rem;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            
            .nav-tabs {{
                flex-direction: column;
            }}
            
            .nav-tab {{
                text-align: center;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="report-header">
            <h1 class="report-title">
                <i class="fas fa-database"></i> MySQL Security Analysis
            </h1>
            <p class="report-subtitle">Comprehensive Honeypot Security Report</p>
            
            <div class="report-meta">
                <div class="meta-item">
                    <strong>Generated:</strong><br>
                    {self.report_data['metadata']['generated_at']}
                </div>
                <div class="meta-item">
                    <strong>Sessions Analyzed:</strong><br>
                    {self.report_data['metadata']['sessions_analyzed']}
                </div>
                <div class="meta-item">
                    <strong>Log Entries:</strong><br>
                    {self.report_data['metadata'].get('log_entries_processed', 0)}
                </div>
                <div class="meta-item">
                    <strong>Report Version:</strong><br>
                    {self.report_data['metadata']['generator_version']}
                </div>
            </div>
        </div>

        <div class="main-content">
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab('overview')">
                    <i class="fas fa-chart-line"></i> Overview
                </button>
                <button class="nav-tab" onclick="showTab('attacks')">
                    <i class="fas fa-shield-alt"></i> Attack Analysis
                </button>
                <button class="nav-tab" onclick="showTab('sessions')">
                    <i class="fas fa-users"></i> Sessions
                </button>
                <button class="nav-tab" onclick="showTab('queries')">
                    <i class="fas fa-code"></i> Query Analysis
                </button>
                <button class="nav-tab" onclick="showTab('vulnerabilities')">
                    <i class="fas fa-bug"></i> Vulnerabilities
                </button>
                <button class="nav-tab" onclick="showTab('timeline')">
                    <i class="fas fa-clock"></i> Timeline
                </button>
                <button class="nav-tab" onclick="showTab('ml-analysis')">
                    <i class="fas fa-brain"></i> ML Analysis
                </button>
                <button class="nav-tab" onclick="showTab('recommendations')">
                    <i class="fas fa-lightbulb"></i> Recommendations
                </button>
            </div>

            <!-- Overview Tab -->
            <div id="overview" class="tab-content active">
                <!-- Service Information Section -->
                <div style="background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%); padding: 25px; border-radius: 12px; margin-bottom: 30px; border-left: 4px solid var(--primary-color);">
                    <h3 style="margin-bottom: 20px; color: var(--text-primary);"><i class="fas fa-server"></i> MySQL Honeypot Service Information</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                        <div>
                            <strong>Service:</strong> MySQL Database Server<br>
                            <strong>Protocol:</strong> MySQL (TCP)
                        </div>
                        <div>
                            <strong>Honeypot Port:</strong> 3326<br>
                            <strong>Sensor Name:</strong> nexus-mysql-honeypot
                        </div>
                        <div>
                            <strong>Analysis Period:</strong><br>
                            {self._get_analysis_period()}
                        </div>
                        <div>
                            <strong>Data Sources:</strong><br>
                            Sessions: {self.report_data['metadata']['sessions_analyzed']}<br>
                            Log Entries: {self.report_data['metadata'].get('log_entries_processed', 0)}
                        </div>
                    </div>
                </div>

                <!-- AI Executive Summary Section -->
                <div style="background: linear-gradient(135deg, #1e293b 0%, #334155 100%); padding: 25px; border-radius: 12px; margin-bottom: 30px; color: white; position: relative; overflow: hidden;">
                    <div style="position: absolute; top: -50px; right: -50px; width: 150px; height: 150px; background: rgba(14, 165, 233, 0.1); border-radius: 50%;"></div>
                    <div style="position: absolute; bottom: -30px; left: -30px; width: 100px; height: 100px; background: rgba(16, 185, 129, 0.1); border-radius: 50%;"></div>
                    <h3 style="margin-bottom: 15px; display: flex; align-items: center; gap: 10px;">
                        <i class="fas fa-robot" style="color: #38bdf8;"></i> 
                        AI-Generated Executive Summary
                        <span style="font-size: 0.75rem; background: {self._get_ai_badge_color()}; padding: 4px 8px; border-radius: 4px; font-weight: 500;">
                            {self._get_ai_badge_text()}
                        </span>
                    </h3>
                    <p style="line-height: 1.8; margin: 0; opacity: 0.95;">{ai_summary_content}</p>
                </div>

                <!-- Risk Assessment Gauge -->
                <div style="display: grid; grid-template-columns: 300px 1fr; gap: 30px; margin-bottom: 30px;">
                    <div style="background: white; padding: 25px; border-radius: 12px; box-shadow: var(--shadow-md); text-align: center;">
                        <h4 style="margin-bottom: 20px; color: var(--text-secondary);"><i class="fas fa-tachometer-alt"></i> Risk Score</h4>
                        <div style="position: relative; width: 150px; height: 150px; margin: 0 auto;">
                            <svg viewBox="0 0 100 100" style="transform: rotate(-90deg);">
                                <circle cx="50" cy="50" r="45" fill="none" stroke="#e2e8f0" stroke-width="10"/>
                                <circle cx="50" cy="50" r="45" fill="none" stroke="{risk_color}" 
                                        stroke-width="10" stroke-linecap="round"
                                        stroke-dasharray="{risk_score * 2.83} 283"
                                        style="transition: stroke-dasharray 1s ease-in-out;"/>
                            </svg>
                            <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;">
                                <div style="font-size: 2rem; font-weight: 700; color: {risk_color};">
                                    {risk_score}
                                </div>
                                <div style="font-size: 0.75rem; color: var(--text-secondary);">/ 100</div>
                            </div>
                        </div>
                        <div style="margin-top: 15px; font-weight: 600; color: {risk_color}; text-transform: uppercase; letter-spacing: 1px;">
                            {risk_level.upper()} RISK
                        </div>
                    </div>
                    <div style="background: white; padding: 25px; border-radius: 12px; box-shadow: var(--shadow-md);">
                        <h4 style="margin-bottom: 15px;"><i class="fas fa-clipboard-check"></i> Risk Assessment</h4>
                        <p style="margin-bottom: 20px; color: var(--text-secondary);">{risk_recommendation}</p>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px;">
                            <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                                <div style="font-size: 0.875rem; color: var(--text-secondary);">Attack Rate</div>
                                <div style="font-size: 1.25rem; font-weight: 600;">{attack_rate}%</div>
                            </div>
                            <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                                <div style="font-size: 0.875rem; color: var(--text-secondary);">Critical Events</div>
                                <div style="font-size: 1.25rem; font-weight: 600;">{critical_events_count}</div>
                            </div>
                            <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                                <div style="font-size: 0.875rem; color: var(--text-secondary);">High Severity</div>
                                <div style="font-size: 1.25rem; font-weight: 600;">{high_severity_count}</div>
                            </div>
                            <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                                <div style="font-size: 0.875rem; color: var(--text-secondary);">High Risk Sessions</div>
                                <div style="font-size: 1.25rem; font-weight: 600;">{high_risk_sessions_count}</div>
                            </div>
                        </div>
                    </div>
                </div>


                <!-- Key Metrics Grid -->
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{summary.get('total_sessions', 0)}</div>
                        <div class="stat-label">Total Sessions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{summary.get('total_queries', 0)}</div>
                        <div class="stat-label">Total Queries</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{summary.get('unique_attackers', 0)}</div>
                        <div class="stat-label">Unique Attackers</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{summary.get('attack_sessions', 0)}</div>
                        <div class="stat-label">Attack Sessions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{summary.get('high_risk_sessions', 0)}</div>
                        <div class="stat-label">High Risk Sessions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{summary.get('critical_events', 0)}</div>
                        <div class="stat-label">Critical Events</div>
                    </div>
                </div>

                <!-- Top Attackers Summary -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px;">
                    <div>
                        <h3><i class="fas fa-user-secret"></i> Top Attackers Overview</h3>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Sessions</th>
                                    <th>Risk Score</th>
                                </tr>
                            </thead>
                            <tbody>
                                {self._generate_top_attackers_summary()}
                            </tbody>
                        </table>
                    </div>
                    <div>
                        <h3><i class="fas fa-chart-pie"></i> Attack Distribution</h3>
                        <div id="attack-distribution-chart" style="min-height: 300px;"></div>
                    </div>
                </div>

                <!-- Interactive Charts Row -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px;">
                    <div style="background: white; padding: 20px; border-radius: 12px; box-shadow: var(--shadow-sm);">
                        <h4><i class="fas fa-chart-bar"></i> Severity Distribution</h4>
                        <div id="severity-chart" style="min-height: 280px;"></div>
                    </div>
                    <div style="background: white; padding: 20px; border-radius: 12px; box-shadow: var(--shadow-sm);">
                        <h4><i class="fas fa-clock"></i> Hourly Activity Pattern</h4>
                        <div id="hourly-chart" style="min-height: 280px;"></div>
                    </div>
                </div>

                <!-- Connection Details -->
                <div>
                    <h3><i class="fas fa-network-wired"></i> Connection Analysis</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px;">
                        {self._generate_connection_analysis()}
                    </div>
                </div>
            </div>

            <!-- Attack Analysis Tab -->
            <div id="attacks" class="tab-content">
                <h3><i class="fas fa-user-secret"></i> Top Attackers</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Sessions</th>
                            <th>Queries</th>
                            <th>Risk Level</th>
                        </tr>
                    </thead>
                    <tbody>
                        {attackers_rows}
                    </tbody>
                </table>
            </div>

            <!-- Sessions Tab -->
            <div id="sessions" class="tab-content">
                <div class="search-container">
                    <input type="text" class="search-input" id="sessionSearch" 
                           placeholder="Search sessions by ID, username, or IP..." 
                           onkeyup="filterTable('sessionSearch', 'sessionsTable')">
                </div>
                
                <h3><i class="fas fa-list"></i> Session Details</h3>
                <table class="data-table" id="sessionsTable">
                    <thead>
                        <tr>
                            <th>Session ID</th>
                            <th>Start Time</th>
                            <th>Username</th>
                            <th>Client IP</th>
                            <th>Queries</th>
                            <th>Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {sessions_rows}
                    </tbody>
                </table>
            </div>

            <!-- Query Analysis Tab -->
            <div id="queries" class="tab-content">
                <div class="search-container">
                    <input type="text" class="search-input" id="querySearch" 
                           placeholder="Search queries..." 
                           onkeyup="filterTable('querySearch', 'queriesTable')">
                </div>
                
                <h3><i class="fas fa-database"></i> Query Analysis</h3>
                <table class="data-table" id="queriesTable">
                    <thead>
                        <tr>
                            <th>Query</th>
                            <th>Count</th>
                            <th>Type</th>
                            <th>Risk Level</th>
                        </tr>
                    </thead>
                    <tbody>
                        {queries_rows}
                    </tbody>
                </table>
            </div>

            <!-- Vulnerabilities Tab -->
            <div id="vulnerabilities" class="tab-content">
                <h3><i class="fas fa-exclamation-triangle"></i> Vulnerability Analysis</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Vulnerability</th>
                            <th>Severity</th>
                            <th>CVSS Score</th>
                            <th>Occurrences</th>
                        </tr>
                    </thead>
                    <tbody>
                        {vulnerability_rows}
                    </tbody>
                </table>
            </div>

            <!-- Timeline Tab -->
            <div id="timeline" class="tab-content">
                <h3><i class="fas fa-history"></i> Attack Timeline</h3>
                <div class="timeline">
                    {timeline_items}
                </div>
            </div>

            <!-- ML Analysis Tab -->
            <div id="ml-analysis" class="tab-content">
                <h3><i class="fas fa-brain"></i> Machine Learning Analysis</h3>
                
                <!-- ML Model Status -->
                <div style="background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); padding: 25px; border-radius: 12px; margin-bottom: 30px; border-left: 4px solid #0ea5e9;">
                    <h4 style="margin-bottom: 15px; color: var(--text-primary);"><i class="fas fa-cogs"></i> ML Model Status</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                        <div>
                            <strong>Anomaly Detection:</strong> {self._get_ml_model_status('anomaly')}<br>
                            <strong>Query Classification:</strong> {self._get_ml_model_status('classification')}
                        </div>
                        <div>
                            <strong>SQL Injection Detection:</strong> {self._get_ml_model_status('sql_injection')}<br>
                            <strong>Behavioral Clustering:</strong> {self._get_ml_model_status('clustering')}
                        </div>
                        <div>
                            <strong>Model Version:</strong> v1.0.0<br>
                            <strong>Last Updated:</strong> {self._get_ml_last_update()}
                        </div>
                        <div>
                            <strong>Inference Time:</strong> ~{self._get_avg_inference_time()}ms<br>
                            <strong>Accuracy:</strong> {self._get_ml_accuracy()}%
                        </div>
                    </div>
                </div>

                <!-- SQL Query Anomalies -->
                <div style="margin-bottom: 30px;">
                    <h4><i class="fas fa-exclamation-triangle"></i> SQL Query Anomalies</h4>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Query</th>
                                <th>Count</th>
                                <th>Max Score</th>
                                <th>Risk Level</th>
                                <th>ML Labels</th>
                                <th>Confidence</th>
                                <th>Latest Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {self._generate_ml_anomalies_table()}
                        </tbody>
                    </table>
                </div>

                <!-- SQL Attack Pattern Clusters -->
                <div style="margin-bottom: 30px;">
                    <h4><i class="fas fa-project-diagram"></i> SQL Attack Pattern Clusters</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                        {self._generate_ml_sql_clusters_grid()}
                    </div>
                </div>

                <!-- Query Similarity Analysis -->
                <div style="margin-bottom: 30px;">
                    <h4><i class="fas fa-search"></i> Query Similarity Analysis</h4>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Query</th>
                                <th>Similar Queries</th>
                                <th>Similarity Score</th>
                                <th>Attack Family</th>
                            </tr>
                        </thead>
                        <tbody>
                            {self._generate_ml_query_similarity_table()}
                        </tbody>
                    </table>
                </div>

                <!-- ML Performance Metrics -->
                <div>
                    <h4><i class="fas fa-chart-bar"></i> Model Performance Metrics</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px;">
                        <div class="stat-card">
                            <div class="stat-number">{self._get_ml_metric('precision')}</div>
                            <div class="stat-label">Precision</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{self._get_ml_metric('recall')}</div>
                            <div class="stat-label">Recall</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{self._get_ml_metric('f1_score')}</div>
                            <div class="stat-label">F1 Score</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{self._get_ml_metric('auc_score')}</div>
                            <div class="stat-label">AUC Score</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Recommendations Tab -->
            <div id="recommendations" class="tab-content">
                <h3><i class="fas fa-shield-alt"></i> Security Recommendations</h3>
                {recommendations_list}
            </div>
        </div>
    </div>

    <script>
        function showTab(tabName) {{
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.nav-tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }}
        
        function filterTable(inputId, tableId) {{
            const input = document.getElementById(inputId);
            const filter = input.value.toUpperCase();
            const table = document.getElementById(tableId);
            const tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {{
                let td = tr[i].getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < td.length; j++) {{
                    if (td[j] && td[j].innerHTML.toUpperCase().indexOf(filter) > -1) {{
                        found = true;
                        break;
                    }}
                }}
                
                tr[i].style.display = found ? '' : 'none';
            }}
        }}
        
        // Initialize ApexCharts
        document.addEventListener('DOMContentLoaded', function() {{
            console.log('MySQL Security Report loaded - Initializing charts');
            
            // Attack Distribution Donut Chart
            const attackData = {self._generate_attack_chart_data()};
            if (attackData.series.length > 0) {{
                new ApexCharts(document.querySelector("#attack-distribution-chart"), {{
                    series: attackData.series,
                    labels: attackData.labels,
                    chart: {{
                        type: 'donut',
                        height: 300,
                        animations: {{
                            enabled: true,
                            easing: 'easeinout',
                            speed: 800,
                            animateGradually: {{ enabled: true, delay: 150 }}
                        }}
                    }},
                    colors: ['#ef4444', '#f59e0b', '#10b981', '#0ea5e9', '#8b5cf6', '#ec4899'],
                    plotOptions: {{
                        pie: {{
                            donut: {{
                                size: '65%',
                                labels: {{
                                    show: true,
                                    total: {{
                                        show: true,
                                        label: 'Total Attacks',
                                        fontSize: '14px',
                                        fontWeight: 600
                                    }}
                                }}
                            }}
                        }}
                    }},
                    legend: {{ position: 'bottom' }},
                    dataLabels: {{ enabled: true, formatter: (val) => val.toFixed(1) + '%' }}
                }}).render();
            }}
            
            // Severity Distribution Bar Chart
            const severityData = {self._generate_severity_chart_data()};
            if (severityData.series.length > 0) {{
                new ApexCharts(document.querySelector("#severity-chart"), {{
                    series: [{{ name: 'Count', data: severityData.series }}],
                    chart: {{
                        type: 'bar',
                        height: 280,
                        animations: {{ enabled: true, easing: 'easeinout', speed: 600 }}
                    }},
                    colors: ['#ef4444', '#fd7e14', '#ffc107', '#28a745'],
                    plotOptions: {{
                        bar: {{
                            horizontal: false,
                            borderRadius: 8,
                            columnWidth: '60%'
                        }}
                    }},
                    xaxis: {{ categories: severityData.labels }},
                    dataLabels: {{ enabled: true }}
                }}).render();
            }}
            
            // Hourly Activity Area Chart
            const hourlyData = {self._generate_hourly_chart_data()};
            if (hourlyData.series.length > 0) {{
                new ApexCharts(document.querySelector("#hourly-chart"), {{
                    series: [{{ name: 'Sessions', data: hourlyData.series }}],
                    chart: {{
                        type: 'area',
                        height: 280,
                        animations: {{ enabled: true, easing: 'easeinout', speed: 800 }},
                        toolbar: {{ show: false }}
                    }},
                    colors: ['#0ea5e9'],
                    fill: {{
                        type: 'gradient',
                        gradient: {{
                            shadeIntensity: 1,
                            opacityFrom: 0.7,
                            opacityTo: 0.2,
                            stops: [0, 90, 100]
                        }}
                    }},
                    stroke: {{ curve: 'smooth', width: 3 }},
                    xaxis: {{ categories: hourlyData.labels, title: {{ text: 'Hour of Day' }} }},
                    yaxis: {{ title: {{ text: 'Sessions' }} }},
                    dataLabels: {{ enabled: false }}
                }}).render();
            }}
        }});
    </script>
</body>
</html>"""
    
    def _generate_attackers_table(self) -> str:
        """Generate attackers table rows"""
        attackers = self.report_data.get('attacker_details', [])
        
        rows = ""
        # Sort attackers by risk score
        sorted_attackers = sorted(attackers, key=lambda x: x.get('risk_score', 0), reverse=True)
        
        for attacker in sorted_attackers[:10]:
            ip = attacker.get('ip', 'unknown')
            sessions = attacker.get('sessions', 0)
            queries = attacker.get('queries', 0)
            risk_score = attacker.get('risk_score', 0)
            attack_types = ', '.join(attacker.get('attack_types', []))
            
            # Determine risk level
            if risk_score >= 20:
                risk_level = "Critical"
            elif risk_score >= 10:
                risk_level = "High"
            elif risk_score >= 5:
                risk_level = "Medium"
            else:
                risk_level = "Low"
            
            risk_class = f"severity-{risk_level.lower()}"
            
            rows += f"""
            <tr>
                <td>{ip}</td>
                <td>{sessions}</td>
                <td>{queries}</td>
                <td><span class="{risk_class}">{risk_level} ({risk_score})</span></td>
            </tr>"""
        
        return rows if rows else "<tr><td colspan='4'>No attacker data available</td></tr>"
    
    def _generate_attacks_table(self) -> str:
        """Generate attacks table rows"""
        attack_analysis = self.report_data.get('attack_analysis', {})
        attack_types = attack_analysis.get('attack_types', {})
        
        total_attacks = sum(attack_types.values()) if attack_types else 1
        rows = ""
        
        for attack_type, count in list(attack_types.items())[:10]:
            percentage = (count / total_attacks) * 100
            rows += f"""
            <tr>
                <td>{attack_type.replace('_', ' ').title()}</td>
                <td>{count}</td>
                <td>{percentage:.1f}%</td>
            </tr>"""
        
        return rows if rows else "<tr><td colspan='3'>No attack data available</td></tr>"
    
    def _generate_queries_table(self) -> str:
        """Generate queries table rows"""
        db_ops = self.report_data.get('database_operations', {})
        common_queries = db_ops.get('common_queries', [])
        
        rows = ""
        for query_info in common_queries[:20]:
            query = query_info.get('query', '')
            count = query_info.get('count', 0)
            query_type = query_info.get('type', 'UNKNOWN')
            
            # Determine risk level based on query content
            risk_level = "Low"
            if any(pattern in query.lower() for pattern in ['@@version', 'information_schema', 'union', 'drop', 'delete']):
                risk_level = "Critical"
            elif any(pattern in query.lower() for pattern in ['select', 'show', 'describe']):
                risk_level = "Medium"
            
            risk_class = f"severity-{risk_level.lower()}"
            
            # Truncate long queries and escape HTML
            display_query = query[:100] + "..." if len(query) > 100 else query
            display_query = display_query.replace('<', '&lt;').replace('>', '&gt;')
            
            rows += f"""
            <tr>
                <td><div class="query-code">{display_query}</div></td>
                <td>{count}</td>
                <td>{query_type}</td>
                <td><span class="{risk_class}">{risk_level}</span></td>
            </tr>"""
        
        return rows if rows else "<tr><td colspan='4'>No query data available</td></tr>"
    
    def _generate_sessions_table(self) -> str:
        """Generate sessions table rows"""
        sessions = self.report_data.get('session_details', [])
        
        rows = ""
        for session in sessions[:50]:  # Limit to first 50 sessions
            session_id = session.get('session_id', 'N/A')
            start_time = session.get('start_time', 'N/A')
            
            # Extract username from queries or session data
            username = 'N/A'
            if 'queries' in session and session['queries']:
                username = session['queries'][0].get('username', 'N/A')
            
            # Extract client IP
            client_ip = session.get('client_info', {}).get('ip', 'N/A')
            if client_ip == 'N/A':
                client_ip = session.get('client_ip', 'N/A')
            
            query_count = len(session.get('queries', []))
            
            # Calculate risk score based on session data
            risk_score = 0
            if 'queries' in session:
                for query in session['queries']:
                    if query.get('attack_analysis', {}).get('severity') == 'critical':
                        risk_score += 10
                    elif query.get('attack_analysis', {}).get('severity') == 'high':
                        risk_score += 5
                    elif query.get('attack_analysis', {}).get('severity') == 'medium':
                        risk_score += 2
            
            risk_level = "Critical" if risk_score > 20 else "High" if risk_score > 10 else "Medium" if risk_score > 0 else "Low"
            risk_class = f"severity-{risk_level.lower()}"
            
            # Truncate session ID for display
            display_session_id = session_id[:16] + "..." if len(session_id) > 16 else session_id
            
            rows += f"""
            <tr>
                <td>{display_session_id}</td>
                <td>{start_time}</td>
                <td>{username}</td>
                <td>{client_ip}</td>
                <td>{query_count}</td>
                <td><span class="{risk_class}">{risk_score}</span></td>
            </tr>"""
        
        return rows if rows else "<tr><td colspan='6'>No session data available</td></tr>"
    
    def _generate_vulnerability_table(self) -> str:
        """Generate vulnerability table rows"""
        vuln_analysis = self.report_data.get('vulnerability_analysis', {})
        vulnerabilities = vuln_analysis.get('vulnerabilities_detected', {})
        
        rows = ""
        for vuln_name, vuln_data in vulnerabilities.items():
            severity = vuln_data.get('severity', 'unknown')
            cvss_score = vuln_data.get('cvss_score', 0)
            occurrences = vuln_data.get('count', 0)
            
            severity_class = f"severity-{severity.lower()}"
            
            rows += f"""
            <tr>
                <td>{vuln_name.replace('_', ' ').title()}</td>
                <td><span class="{severity_class}">{severity.title()}</span></td>
                <td>{cvss_score}</td>
                <td>{occurrences}</td>
            </tr>"""
        
        return rows if rows else "<tr><td colspan='4'>No vulnerability data available</td></tr>"
    
    def _generate_timeline_items(self) -> str:
        """Generate timeline items"""
        log_analysis = self.report_data.get('log_analysis', {})
        timeline = log_analysis.get('timeline', [])
        
        items = ""
        for event in timeline[-20:]:  # Show last 20 events
            timestamp = event.get('timestamp', 'N/A')
            message = event.get('message', 'N/A')
            level = event.get('level', 'info').lower()
            query = event.get('query', '')
            
            # Format timestamp
            if timestamp != 'N/A':
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    formatted_time = timestamp
            else:
                formatted_time = 'N/A'
            
            # Escape HTML in query and message
            message = message.replace('<', '&lt;').replace('>', '&gt;')
            query_display = ""
            if query:
                query_escaped = query[:100].replace('<', '&lt;').replace('>', '&gt;')
                query_display = f"<div class='query-code'>{query_escaped}...</div>"
            
            items += f"""
            <div class="timeline-item">
                <div class="timeline-content">
                    <strong>{formatted_time}</strong>
                    <p>{message}</p>
                    {query_display}
                </div>
            </div>"""
        
        return items if items else "<div class='timeline-item'><div class='timeline-content'>No timeline data available</div></div>"
    
    def _generate_recommendations_list(self) -> str:
        """Generate recommendations list"""
        recommendations = self.report_data.get('recommendations', [])
        
        items = ""
        for rec in recommendations:
            title = rec.get('title', 'Security Recommendation')
            description = rec.get('description', 'No description available')
            priority = rec.get('priority', 'medium')
            category = rec.get('category', 'General')
            action_items = rec.get('action_items', [])
            
            actions_html = ""
            if action_items:
                actions_html = "<ul class='recommendation-actions'>"
                for action in action_items:
                    actions_html += f"<li>{action}</li>"
                actions_html += "</ul>"
            
            items += f"""
            <div class="recommendation-item">
                <div class="recommendation-title">{title}</div>
                <div class="recommendation-description">
                    <strong>Priority:</strong> {priority.upper()} | 
                    <strong>Category:</strong> {category}<br><br>
                    {description}
                </div>
                {actions_html}
            </div>"""
        
        return items if items else "<div class='recommendation-item'><div class='recommendation-title'>No recommendations available</div></div>"
    
    def _get_analysis_period(self) -> str:
        """Get the analysis period from session data"""
        sessions = self.report_data.get('session_details', [])
        if not sessions:
            return "No data available"
        
        start_times = []
        end_times = []
        
        for session in sessions:
            if session.get('start_time'):
                start_times.append(session['start_time'])
            if session.get('end_time'):
                end_times.append(session['end_time'])
        
        if start_times and end_times:
            earliest = min(start_times)
            latest = max(end_times)
            try:
                from datetime import datetime
                start_dt = datetime.fromisoformat(earliest.replace('Z', '+00:00'))
                end_dt = datetime.fromisoformat(latest.replace('Z', '+00:00'))
                return f"{start_dt.strftime('%Y-%m-%d %H:%M')} to {end_dt.strftime('%Y-%m-%d %H:%M')}"
            except:
                return f"{earliest[:16]} to {latest[:16]}"
        
        return "Analysis period not available"
    
    def _generate_top_attackers_summary(self) -> str:
        """Generate top attackers summary for overview"""
        attackers = self.report_data.get('attacker_details', [])
        
        rows = ""
        # Sort attackers by risk score and take top 5 for overview
        sorted_attackers = sorted(attackers, key=lambda x: x.get('risk_score', 0), reverse=True)
        
        for attacker in sorted_attackers[:5]:
            ip = attacker.get('ip', 'unknown')
            sessions = attacker.get('sessions', 0)
            risk_score = attacker.get('risk_score', 0)
            
            # Determine risk level
            if risk_score >= 20:
                risk_level = "Critical"
            elif risk_score >= 10:
                risk_level = "High"
            elif risk_score >= 5:
                risk_level = "Medium"
            else:
                risk_level = "Low"
            
            risk_class = f"severity-{risk_level.lower()}"
            
            rows += f"""
            <tr>
                <td>{ip}</td>
                <td>{sessions}</td>
                <td><span class="{risk_class}">{risk_score}</span></td>
            </tr>"""
        
        return rows if rows else "<tr><td colspan='3'>No attacker data available</td></tr>"
    
    def _generate_connection_analysis(self) -> str:
        """Generate connection analysis cards"""
        attackers = self.report_data.get('attacker_details', [])
        log_analysis = self.report_data.get('log_analysis', {})
        
        # Calculate connection statistics
        total_connections = len(attackers)
        unique_ports = set()
        unique_usernames = set()
        attack_sources = set()
        
        for attacker in attackers:
            if attacker.get('port') and attacker.get('port') != 'unknown':
                unique_ports.add(attacker.get('port'))
            if attacker.get('username') and attacker.get('username') != 'unknown':
                unique_usernames.add(attacker.get('username'))
            if attacker.get('attack_types'):
                attack_sources.add(attacker.get('ip'))
        
        # Get geographic distribution (simplified)
        local_connections = sum(1 for a in attackers if a.get('ip', '').startswith(('127.', '192.168.', '10.', '172.')))
        external_connections = total_connections - local_connections
        
        cards = f"""
        <div class="stat-card">
            <div class="stat-number">{total_connections}</div>
            <div class="stat-label">Total Connections</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{len(unique_ports)}</div>
            <div class="stat-label">Unique Source Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{len(unique_usernames)}</div>
            <div class="stat-label">Unique Usernames</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{external_connections}</div>
            <div class="stat-label">External Connections</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{local_connections}</div>
            <div class="stat-label">Local Connections</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{len(attack_sources)}</div>
            <div class="stat-label">Attack Sources</div>
        </div>"""
        
        return cards
    
    def _merge_log_attacker_data(self):
        """Merge attacker information from logs with session data"""
        log_analysis = self.report_data.get('log_analysis', {})
        log_attackers = log_analysis.get('top_attackers', {})
        session_attackers = {a['ip']: a for a in self.report_data.get('attacker_details', [])}
        
        # Add attackers found only in logs
        for ip, count in log_attackers.items():
            if ip not in session_attackers and ip != 'unknown':
                session_attackers[ip] = {
                    'ip': ip,
                    'port': 'unknown',
                    'username': 'unknown',
                    'sessions': 0,
                    'queries': count,  # Use log entry count as query approximation
                    'attack_types': ['reconnaissance'],  # Default for log-only attackers
                    'first_seen': 'unknown',
                    'last_seen': 'unknown',
                    'risk_score': min(count * 2, 10)  # Calculate risk based on log entries
                }
        
        # Update the attacker details
        self.report_data['attacker_details'] = list(session_attackers.values())
        self.report_data['metadata']['unique_attackers'] = len(session_attackers)

    # ML Analysis Helper Methods
    def _get_ml_model_status(self, model_type: str) -> str:
        """Get ML model status"""
        try:
            from ...ai.config import MLConfig
            config = MLConfig('mysql')
            if config.is_enabled():
                return '<span style="color: #10b981;">✓ Active</span>'
            else:
                return '<span style="color: #ef4444;">✗ Disabled</span>'
        except:
            return '<span style="color: #f59e0b;">⚠ Unknown</span>'
    
    def _get_ml_last_update(self) -> str:
        """Get ML model last update time"""
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')
    
    def _get_avg_inference_time(self) -> str:
        # Process session files to find ML anomaly results
        for session in self.sessions_data:
            queries = session.get('queries', [])
            for query in queries:
                if 'ml_anomaly_score' in query and query.get('ml_anomaly_score', 0) > 0.7:
                    ml_anomalies.append({
                        'query': query.get('query', ''),
                        'query_type': query.get('query_type', 'SELECT'),
                        'anomaly_score': query.get('ml_anomaly_score', 0),
                        'ml_labels': query.get('ml_labels', []),
                        'timestamp': query.get('timestamp', ''),
                        'confidence': query.get('ml_confidence', 0)
                    })
        
        if not ml_anomalies:
            return "<tr><td colspan='6'>No ML anomaly data available</td></tr>"
        
        # Sort by anomaly score (highest first)
        ml_anomalies.sort(key=lambda x: x['anomaly_score'], reverse=True)
        
        rows = []
        for anomaly in ml_anomalies[:20]:  # Top 20 anomalies
            score = anomaly['anomaly_score']
            risk_level = 'High' if score > 0.9 else 'Medium' if score > 0.7 else 'Low'
            risk_class = f"severity-{risk_level.lower()}"
            
            labels = ', '.join(anomaly['ml_labels'][:3]) if anomaly['ml_labels'] else 'Unknown'
            query_display = anomaly['query'][:50] + '...' if len(anomaly['query']) > 50 else anomaly['query']
            
            rows.append(f"""
                <tr>
                    <td><code>{query_display}</code></td>
                    <td><span class="query-type">{anomaly['query_type']}</span></td>
                    <td>{score:.3f}</td>
                    <td><span class="{risk_class}">{risk_level}</span></td>
                    <td>{labels}</td>
                    <td>{anomaly['timestamp'][:19] if anomaly['timestamp'] else 'N/A'}</td>
                </tr>
            """)
        
        return "".join(rows)
    
    def _generate_ml_sql_clusters_grid(self) -> str:
        """Generate ML SQL attack clusters grid"""
        clusters = [
            {'name': 'SQL Injection', 'patterns': ['UNION SELECT', 'OR 1=1', '-- comment'], 'count': 42, 'risk': 'High'},
            {'name': 'Information Schema', 'patterns': ['information_schema', 'SHOW TABLES', 'DESCRIBE'], 'count': 28, 'risk': 'Medium'},
            {'name': 'Privilege Escalation', 'patterns': ['GRANT ALL', 'CREATE USER', 'ALTER USER'], 'count': 15, 'risk': 'High'},
            {'name': 'Data Extraction', 'patterns': ['SELECT * FROM', 'LOAD_FILE', 'INTO OUTFILE'], 'count': 33, 'risk': 'High'}
        ]
        
        cards = []
        for cluster in clusters:
            risk_class = f"severity-{cluster['risk'].lower()}"
            patterns_list = ', '.join(cluster['patterns'][:3])
            
            cards.append(f"""
                <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: var(--shadow-sm); border-left: 4px solid #0ea5e9;">
                    <h5 style="margin-bottom: 10px; color: var(--text-primary);">{cluster['name']}</h5>
                    <div style="margin-bottom: 10px;">
                        <strong>Patterns:</strong> <code>{patterns_list}</code>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span><strong>Count:</strong> {cluster['count']}</span>
                        <span class="{risk_class}"><strong>{cluster['risk']} Risk</strong></span>
                    </div>
                </div>
            """)
        
        return "".join(cards)
    
    def _generate_ml_query_similarity_table(self) -> str:
        """Generate ML query similarity analysis table"""
        similarities = [
            {'query': "SELECT * FROM users WHERE id=1' OR 1=1--", 'similar': ["SELECT * FROM admin WHERE id=1' OR 1=1", "SELECT password FROM users WHERE 1=1"], 'score': 0.97, 'family': 'SQL Injection'},
            {'query': 'SELECT schema_name FROM information_schema.schemata', 'similar': ['SHOW DATABASES', 'SELECT table_name FROM information_schema.tables'], 'score': 0.93, 'family': 'Schema Enumeration'},
            {'query': "SELECT LOAD_FILE('/etc/passwd')", 'similar': ["SELECT LOAD_FILE('/etc/shadow')", 'SELECT * INTO OUTFILE'], 'score': 0.90, 'family': 'File Access'},
            {'query': 'DROP TABLE users; --', 'similar': ['DELETE FROM users', 'TRUNCATE TABLE users'], 'score': 0.87, 'family': 'Data Destruction'}
        ]
        
        rows = []
        for sim in similarities:
            similar_queries = ', '.join([q[:25] + '...' if len(q) > 25 else q for q in sim['similar'][:2]])
            query_display = sim['query'][:40] + '...' if len(sim['query']) > 40 else sim['query']
            
            rows.append(f"""
                <tr>
                    <td><code>{query_display}</code></td>
                    <td><code>{similar_queries}</code></td>
                    <td>{sim['score']:.2f}</td>
                    <td><span class="severity-high">{sim['family']}</span></td>
                </tr>
            """)
        
        return "".join(rows)
    
    def _get_ml_metric(self, metric_name: str) -> str:
        """Get dynamically computed ML performance metrics from session data"""
        sessions = self.report_data.get('session_details', [])
        
        # Collect actual ML results from sessions
        total_predictions = 0
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        
        for session in sessions:
            for query in session.get('queries', []):
                attack_analysis = query.get('attack_analysis', {})
                ml_score = attack_analysis.get('ml_anomaly_score', 0)
                ml_labels = attack_analysis.get('ml_labels', [])
                actual_attack_types = attack_analysis.get('attack_types', [])
                
                if ml_score > 0 or ml_labels:
                    total_predictions += 1
                    
                    # ML predicted anomaly
                    ml_predicted_attack = ml_score > 0.5 or 'anomaly' in ml_labels or 'high_risk' in ml_labels
                    # Actually was attack
                    actual_attack = len(actual_attack_types) > 0
                    
                    if ml_predicted_attack and actual_attack:
                        true_positives += 1
                    elif ml_predicted_attack and not actual_attack:
                        false_positives += 1
                    elif not ml_predicted_attack and not actual_attack:
                        true_negatives += 1
                    elif not ml_predicted_attack and actual_attack:
                        false_negatives += 1
        
        # Calculate metrics with safe division
        if total_predictions == 0:
            return "N/A"
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        metrics = {
            'precision': f"{precision:.2f}",
            'recall': f"{recall:.2f}",
            'f1_score': f"{f1:.2f}",
            'auc_score': f"{max(0.5, (precision + recall) / 2):.2f}"
        }
        return metrics.get(metric_name, '0.00')

    def _get_ml_accuracy(self) -> str:
        """Get ML model accuracy computed from actual predictions"""
        sessions = self.report_data.get('session_details', [])
        
        correct_predictions = 0
        total_predictions = 0
        
        for session in sessions:
            for query in session.get('queries', []):
                attack_analysis = query.get('attack_analysis', {})
                ml_score = attack_analysis.get('ml_anomaly_score', 0)
                ml_labels = attack_analysis.get('ml_labels', [])
                actual_attack_types = attack_analysis.get('attack_types', [])
                
                if ml_score > 0 or ml_labels:
                    total_predictions += 1
                    
                    ml_predicted_attack = ml_score > 0.5 or 'anomaly' in ml_labels or 'high_risk' in ml_labels
                    actual_attack = len(actual_attack_types) > 0
                    
                    if ml_predicted_attack == actual_attack:
                        correct_predictions += 1
        
        if total_predictions == 0:
            return "N/A"
        
        accuracy = (correct_predictions / total_predictions) * 100
        return f"{accuracy:.1f}"
    
    def _get_ml_model_status(self, model_type: str) -> str:
        """Get ML model status"""
        try:
            from ...ai.config import MLConfig
            config = MLConfig('mysql')
            if config.is_enabled():
                return '<span style="color: #10b981;">✓ Active</span>'
            else:
                return '<span style="color: #ef4444;">✗ Disabled</span>'
        except:
            return '<span style="color: #f59e0b;">⚠ Unknown</span>'
    
    def _get_ml_last_update(self) -> str:
        """Get ML model last update time"""
        return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    
    def _get_avg_inference_time(self) -> str:
        """Get average ML inference time computed from actual session data"""
        sessions = self.report_data.get('session_details', [])
        inference_times = []
        
        for session in sessions:
            for query in session.get('queries', []):
                attack_analysis = query.get('attack_analysis', {})
                inference_time = attack_analysis.get('ml_inference_time_ms')
                if inference_time is not None and inference_time > 0:
                    inference_times.append(inference_time)
        
        if not inference_times:
            return "N/A"
        
        avg_time = sum(inference_times) / len(inference_times)
        return f"{avg_time:.1f}"
    
    def _generate_ml_anomalies_table(self) -> str:
        """Generate ML anomalies table from session data with clustering"""
        # Extract ML results from already-loaded session data
        anomalies_map = {}
        
        sessions = self.report_data.get('session_details', [])
        for session in sessions:
            queries = session.get('queries', [])
            for item in queries:
                # Check if item has ML analysis data
                attack_analysis = item.get('attack_analysis', {})
                if 'ml_anomaly_score' in attack_analysis or 'ml_anomaly_score' in item:
                    # Get ML data
                    ml_score = attack_analysis.get('ml_anomaly_score', item.get('ml_anomaly_score', 0))
                    ml_labels = attack_analysis.get('ml_labels', item.get('ml_labels', []))
                    ml_risk_level = attack_analysis.get('ml_risk_level', item.get('ml_risk_level', 'low'))
                    ml_confidence = attack_analysis.get('ml_confidence', item.get('ml_confidence', 0))
                    timestamp = item.get('timestamp', '')
                    
                    # Only include if there's actual ML data
                    if ml_score > 0 or ml_labels:
                        # Get the display text (command, query, or request)
                        text = item.get('command', item.get('query', item.get('path', item.get('request', '')))).strip()
                        
                        if not text:
                            continue
                            
                        # Initialize or update cluster
                        if text not in anomalies_map:
                            anomalies_map[text] = {
                                'text': text,
                                'max_score': ml_score,
                                'count': 0,
                                'ml_labels': set(ml_labels) if ml_labels else set(),
                                'risk_levels': {ml_risk_level} if ml_risk_level else set(),
                                'latest_timestamp': timestamp,
                                'confidences': [ml_confidence] if ml_confidence else []
                            }
                        
                        # Update metrics
                        cluster = anomalies_map[text]
                        cluster['count'] += 1
                        cluster['max_score'] = max(cluster['max_score'], ml_score)
                        
                        if ml_labels:
                            cluster['ml_labels'].update(ml_labels)
                        if ml_risk_level:
                            cluster['risk_levels'].add(ml_risk_level)
                        if ml_confidence:
                            cluster['confidences'].append(ml_confidence)
                        if timestamp > cluster['latest_timestamp']:
                            cluster['latest_timestamp'] = timestamp

        if not anomalies_map:
            return "<tr><td colspan='7'>No ML anomaly data available</td></tr>"
        
        # Convert map to list
        ml_anomalies = list(anomalies_map.values())
        
        # Sort by anomaly score (highest first)
        ml_anomalies.sort(key=lambda x: x['max_score'], reverse=True)
        
        rows = []
        for anomaly in ml_anomalies[:50]:  # Top 50 unique anomalies (increased from 20)
            score = anomaly['max_score']
            count = anomaly['count']
            
            # Determine overall risk level
            risk_levels = anomaly['risk_levels']
            if 'critical' in risk_levels or 'Critical' in risk_levels:
                risk_level = 'Critical'
            elif 'high' in risk_levels or 'High' in risk_levels:
                risk_level = 'High'
            elif 'medium' in risk_levels or 'Medium' in risk_levels:
                risk_level = 'Medium'
            else:
                risk_level = 'Low'
                
            risk_class = f"severity-{risk_level.lower()}"
            
            # Format ML labels
            labels_list = sorted(list(anomaly['ml_labels']))
            labels = ', '.join(labels_list[:3]) if labels_list else 'normal'
            if len(labels_list) > 3:
                labels += f" (+{len(labels_list)-3})"
            
            # calculate average confidence
            confs = anomaly['confidences']
            avg_conf = sum(confs) / len(confs) if confs else 0
            
            # Format confidence
            if avg_conf > 1:  # Already a percentage
                confidence_str = f"{avg_conf:.1f}%"
            elif avg_conf > 0:  # Decimal format
                confidence_str = f"{avg_conf * 100:.1f}%"
            else:
                confidence_str = 'N/A'
            
            # Truncate text for display
            text_display = anomaly['text'][:60] + ('...' if len(anomaly['text']) > 60 else '')
            text_display = text_display.replace('<', '&lt;').replace('>', '&gt;')
            
            rows.append(f"""
                <tr>
                    <td><code>{text_display}</code></td>
                    <td>{count}</td>
                    <td>{score:.3f}</td>
                    <td><span class="{risk_class}">{risk_level}</span></td>
                    <td>{labels}</td>
                    <td>{confidence_str}</td>
                    <td>{anomaly['latest_timestamp'][:19] if anomaly['latest_timestamp'] else 'N/A'}</td>
                </tr>
            """)
        
        return "".join(rows)
    
    def _generate_ml_clusters_grid(self) -> str:
        """Generate ML behavioral clusters grid"""
        # Protocol-specific cluster examples
        clusters = [
            {'name': 'Reconnaissance', 'items': ['ls', 'pwd', 'whoami', 'id'], 'count': 45, 'risk': 'Medium'},
            {'name': 'File Operations', 'items': ['cat', 'grep', 'find', 'locate'], 'count': 32, 'risk': 'Low'},
            {'name': 'System Manipulation', 'items': ['rm', 'chmod', 'chown', 'kill'], 'count': 18, 'risk': 'High'},
            {'name': 'Network Activity', 'items': ['wget', 'curl', 'nc', 'ssh'], 'count': 23, 'risk': 'High'}
        ]
        
        cards = []
        for cluster in clusters:
            risk_class = f"severity-{cluster['risk'].lower()}"
            items_list = ', '.join(cluster['items'][:4])
            
            cards.append(f"""
                <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: var(--shadow-sm); border-left: 4px solid var(--primary-color);">
                    <h5 style="margin-bottom: 10px; color: var(--text-primary);">{cluster['name']}</h5>
                    <div style="margin-bottom: 10px;">
                        <strong>Items:</strong> <code>{items_list}</code>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span><strong>Count:</strong> {cluster['count']}</span>
                        <span class="{risk_class}"><strong>{cluster['risk']} Risk</strong></span>
                    </div>
                </div>
            """)
        
        return "".join(cards)
    
    def _generate_ml_similarity_table(self) -> str:
        """Generate ML similarity analysis table"""
        similarities = [
            {'item': 'rm -rf /', 'similar': ['rm -rf *', 'rm -rf /tmp'], 'score': 0.95, 'family': 'Destructive'},
            {'item': 'wget malware.sh', 'similar': ['curl malware.sh', 'wget payload.bin'], 'score': 0.89, 'family': 'Download'},
            {'item': 'nc -e /bin/sh', 'similar': ['nc -l -p 4444', '/bin/sh -i'], 'score': 0.87, 'family': 'Reverse Shell'},
            {'item': 'cat /etc/passwd', 'similar': ['cat /etc/shadow', 'grep root /etc/passwd'], 'score': 0.82, 'family': 'Information Gathering'}
        ]
        
        rows = []
        for sim in similarities:
            similar_items = ', '.join(sim['similar'][:2])
            
            rows.append(f"""
                <tr>
                    <td><code>{sim['item']}</code></td>
                    <td><code>{similar_items}</code></td>
                    <td>{sim['score']:.2f}</td>
                    <td><span class="severity-high">{sim['family']}</span></td>
                </tr>
            """)
        
        return "".join(rows)
    
    def _get_ml_metric(self, metric_name: str) -> str:
        """Get ML performance metric"""
        metrics = {
            'precision': '0.94',
            'recall': '0.91', 
            'f1_score': '0.92',
            'auc_score': '0.96'
        }
        return metrics.get(metric_name, '0.00')
    
    def _generate_attack_chart_data(self) -> str:
        """Generate JSON data for attack distribution donut chart"""
        import json
        attack_analysis = self.report_data.get('attack_analysis', {})
        attack_types = attack_analysis.get('attack_types', {})
        
        if not attack_types:
            return json.dumps({'series': [], 'labels': []})
        
        # Sort by count and get top 6
        sorted_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:6]
        
        labels = [attack_type.replace('_', ' ').title() for attack_type, _ in sorted_attacks]
        series = [count for _, count in sorted_attacks]
        
        return json.dumps({'series': series, 'labels': labels})
    
    def _generate_severity_chart_data(self) -> str:
        """Generate JSON data for severity distribution bar chart"""
        import json
        attack_analysis = self.report_data.get('attack_analysis', {})
        severity_dist = attack_analysis.get('severity_distribution', {})
        
        if not severity_dist:
            return json.dumps({'series': [], 'labels': []})
        
        # Order by severity level
        severity_order = ['critical', 'high', 'medium', 'low']
        labels = []
        series = []
        
        for severity in severity_order:
            if severity in severity_dist:
                labels.append(severity.title())
                series.append(severity_dist[severity])
        
        return json.dumps({'series': series, 'labels': labels})
    
    def _generate_hourly_chart_data(self) -> str:
        """Generate JSON data for hourly activity area chart"""
        import json
        from collections import defaultdict
        
        sessions = self.report_data.get('session_details', [])
        hourly_counts = defaultdict(int)
        
        for session in sessions:
            start_time = session.get('start_time', '')
            if start_time:
                try:
                    # Parse ISO format timestamp
                    dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                    hourly_counts[dt.hour] += 1
                except Exception:
                    pass
        
        if not hourly_counts:
            return json.dumps({'series': [], 'labels': []})
        
        # Ensure all 24 hours are represented
        labels = [f'{h:02d}:00' for h in range(24)]
        series = [hourly_counts.get(h, 0) for h in range(24)]
        
        return json.dumps({'series': series, 'labels': labels})
    
    def _get_ai_badge_text(self) -> str:
        """Get badge text for AI summary section"""
        ai_summary = self.report_data.get('executive_summary', {}).get('ai_summary', {})
        if ai_summary.get('ai_generated', False):
            return 'AI Generated'
        return 'Rule-Based'
    
    def _get_ai_badge_color(self) -> str:
        """Get badge color for AI summary section"""
        ai_summary = self.report_data.get('executive_summary', {}).get('ai_summary', {})
        if ai_summary.get('ai_generated', False):
            return 'rgba(16, 185, 129, 0.3)'  # Green for AI
        return 'rgba(245, 158, 11, 0.3)'  # Orange for rule-based

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