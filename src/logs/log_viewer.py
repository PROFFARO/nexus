#!/usr/bin/env python3
"""
NEXUS Honeypot Log Viewer - Parse and display session conversations
"""

import json
import os
import sys
import argparse
import datetime
from base64 import b64decode
from pathlib import Path
from typing import Dict, List, Any, Optional

# Import ML components
try:
    sys.path.append(str(Path(__file__).parent.parent))
    from ai.detectors import MLDetector
    from ai.config import MLConfig
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    print(f"Warning: ML components not available. Install dependencies or check ai module: {e}")


class LogViewer:
    def __init__(self, service: str):
        self.service = service
        self.base_dir = Path(__file__).parent.parent
        
        # Initialize ML detector if available
        self.ml_detector = None
        if ML_AVAILABLE:
            try:
                ml_config = MLConfig(service)
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector(service, ml_config)
                    print(f"✅ ML detector initialized for {service.upper()} log analysis")
            except Exception as e:
                print(f"⚠️ Failed to initialize ML detector: {e}")
                self.ml_detector = None
        
    def parse_ssh_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                      filter_type: str = 'all') -> Dict[str, Any]:
        """Parse SSH log file and extract conversations"""
        conversations = {}
        
        if not os.path.exists(log_file):
            raise FileNotFoundError(f"Log file not found: {log_file}")
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    task_name = log_entry.get('task_name', 'unknown')
                    message = log_entry.get('message', '')
                    
                    if session_id and session_id not in task_name:
                        continue
                    
                    if task_name not in conversations:
                        conversations[task_name] = {
                            'session_id': task_name,
                            'src_ip': log_entry.get('src_ip', 'unknown'),
                            'entries': []
                        }
                    
                    entry = {
                        'timestamp': log_entry.get('timestamp', ''),
                        'message': message,
                        'level': log_entry.get('level', 'INFO'),
                        'raw': log_entry
                    }
                    
                    # Decode base64 details
                    if decode and 'details' in log_entry:
                        try:
                            decoded = b64decode(log_entry['details']).decode('utf-8')
                            entry['decoded_details'] = decoded
                        except:
                            entry['decoded_details'] = 'Failed to decode'
                    
                    # Apply filters
                    if filter_type == 'commands' and 'User input' not in message:
                        continue
                    elif filter_type == 'responses' and 'LLM response' not in message:
                        continue
                    elif filter_type == 'attacks' and 'attack' not in message.lower():
                        continue
                    
                    conversations[task_name]['entries'].append(entry)
                    
                except (json.JSONDecodeError, Exception):
                    continue
        
        return conversations
    
    def parse_ftp_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                      filter_type: str = 'all') -> Dict[str, Any]:
        """Parse FTP log file and extract conversations"""
        conversations = {}
        
        if not os.path.exists(log_file):
            raise FileNotFoundError(f"Log file not found: {log_file}")
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    task_name = log_entry.get('task_name', 'unknown')
                    message = log_entry.get('message', '')
                    
                    if session_id and session_id not in task_name:
                        continue
                    
                    if task_name not in conversations:
                        conversations[task_name] = {
                            'session_id': task_name,
                            'src_ip': log_entry.get('src_ip', 'unknown'),
                            'entries': []
                        }
                    
                    entry = {
                        'timestamp': log_entry.get('timestamp', ''),
                        'message': message,
                        'level': log_entry.get('level', 'INFO'),
                        'raw': log_entry
                    }
                    
                    # Decode base64 details
                    if decode and 'details' in log_entry:
                        try:
                            decoded = b64decode(log_entry['details']).decode('utf-8')
                            entry['decoded_details'] = decoded
                        except:
                            entry['decoded_details'] = 'Failed to decode'
                    
                    # Apply filters
                    if filter_type == 'commands' and 'FTP command' not in message:
                        continue
                    elif filter_type == 'responses' and 'FTP response' not in message:
                        continue
                    elif filter_type == 'attacks' and 'attack' not in message.lower():
                        continue
                    
                    conversations[task_name]['entries'].append(entry)
                    
                except (json.JSONDecodeError, Exception):
                    continue
        
        return conversations
    
    def parse_http_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                       filter_type: str = 'all') -> Dict[str, Any]:
        """Parse HTTP log file and extract conversations"""
        conversations = {}
        
        if not os.path.exists(log_file):
            raise FileNotFoundError(f"Log file not found: {log_file}")
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    task_name = log_entry.get('task_name', 'unknown')
                    message = log_entry.get('message', '')
                    
                    if session_id and session_id not in task_name:
                        continue
                    
                    if task_name not in conversations:
                        conversations[task_name] = {
                            'session_id': task_name,
                            'src_ip': log_entry.get('src_ip', 'unknown'),
                            'entries': []
                        }
                    
                    entry = {
                        'timestamp': log_entry.get('timestamp', ''),
                        'message': message,
                        'level': log_entry.get('level', 'INFO'),
                        'raw': log_entry
                    }
                    
                    # Apply filters
                    if filter_type == 'commands' and 'HTTP request' not in message:
                        continue
                    elif filter_type == 'responses' and 'HTTP response' not in message:
                        continue
                    elif filter_type == 'attacks' and 'attack' not in message.lower():
                        continue
                    
                    conversations[task_name]['entries'].append(entry)
                    
                except (json.JSONDecodeError, Exception):
                    continue
        
        return conversations
    
    def parse_mysql_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                        filter_type: str = 'all') -> Dict[str, Any]:
        """Parse MySQL log file and extract conversations"""
        conversations = {}
        
        if not os.path.exists(log_file):
            raise FileNotFoundError(f"Log file not found: {log_file}")
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    task_name = log_entry.get('task_name', 'unknown')
                    message = log_entry.get('message', '')
                    
                    if session_id and session_id not in task_name:
                        continue
                    
                    if task_name not in conversations:
                        # Try to get client IP from connection info in log entries
                        client_ip = log_entry.get('client_ip', log_entry.get('src_ip', 'unknown'))
                        conversations[task_name] = {
                            'session_id': task_name,
                            'src_ip': client_ip,
                            'entries': []
                        }
                    else:
                        # Update IP if we find it in subsequent entries
                        if 'client_ip' in log_entry and log_entry['client_ip'] != 'unknown':
                            conversations[task_name]['src_ip'] = log_entry['client_ip']
                    
                    entry = {
                        'timestamp': log_entry.get('timestamp', ''),
                        'message': message,
                        'level': log_entry.get('level', 'INFO'),
                        'raw': log_entry
                    }
                    
                    # Decode base64 details
                    if decode and 'details' in log_entry:
                        try:
                            decoded = b64decode(log_entry['details']).decode('utf-8')
                            entry['decoded_details'] = decoded
                        except:
                            entry['decoded_details'] = 'Failed to decode'
                    
                    # Apply filters
                    if filter_type == 'commands' and 'MySQL query received' not in message:
                        continue
                    elif filter_type == 'responses' and ('LLM raw response' not in message and 'MySQL response' not in message):
                        continue
                    elif filter_type == 'attacks' and 'attack' not in message.lower():
                        continue
                    
                    conversations[task_name]['entries'].append(entry)
                    
                except (json.JSONDecodeError, Exception):
                    continue
        
        return conversations
    
    def parse_smb_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                      filter_type: str = 'all') -> Dict[str, Any]:
        """Parse SMB log file and extract conversations"""
        conversations = {}
        
        if not os.path.exists(log_file):
            raise FileNotFoundError(f"Log file not found: {log_file}")
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    task_name = log_entry.get('task_name', 'unknown')
                    message = log_entry.get('message', '')
                    
                    if session_id and session_id not in task_name:
                        continue
                    
                    if task_name not in conversations:
                        conversations[task_name] = {
                            'session_id': task_name,
                            'src_ip': log_entry.get('src_ip', 'unknown'),
                            'entries': []
                        }
                    
                    entry = {
                        'timestamp': log_entry.get('timestamp', ''),
                        'message': message,
                        'level': log_entry.get('level', 'INFO'),
                        'raw': log_entry
                    }
                    
                    # Decode base64 details
                    if decode and 'details' in log_entry:
                        try:
                            decoded = b64decode(log_entry['details']).decode('utf-8')
                            entry['decoded_details'] = decoded
                        except:
                            entry['decoded_details'] = 'Failed to decode'
                    
                    # Apply filters
                    if filter_type == 'commands' and 'SMB command' not in message:
                        continue
                    elif filter_type == 'responses' and 'SMB response' not in message:
                        continue
                    elif filter_type == 'attacks' and 'attack' not in message.lower():
                        continue
                    
                    conversations[task_name]['entries'].append(entry)
                    
                except (json.JSONDecodeError, Exception):
                    continue
        
        return conversations
    
    def analyze_log_entry_ml(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single log entry using ML"""
        if not self.ml_detector:
            return {}
        
        try:
            # Extract relevant data based on service type
            ml_data = self._extract_ml_features_from_entry(entry)
            if not ml_data:
                return {}
            
            # Get ML analysis
            ml_results = self.ml_detector.score(ml_data)
            
            # Add timestamp for tracking
            ml_results['ml_analysis_timestamp'] = datetime.datetime.now().isoformat()
            
            return ml_results
            
        except Exception as e:
            print(f"⚠️ ML analysis failed for entry: {e}")
            return {}
    
    def _extract_ml_features_from_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract ML features from log entry based on service type"""
        raw_data = entry.get('raw', {})
        message = entry.get('message', '')
        
        if self.service == 'ssh':
            # Extract SSH command data
            if 'command' in raw_data:
                return {
                    'command': raw_data['command'],
                    'session_data': {
                        'command_count': 1,
                        'failed_commands': 0,
                        'bytes_transferred': len(raw_data['command'])
                    }
                }
            elif 'User input' in message and 'decoded_details' in entry:
                return {
                    'command': entry['decoded_details'],
                    'session_data': {
                        'command_count': 1,
                        'failed_commands': 0,
                        'bytes_transferred': len(entry['decoded_details'])
                    }
                }
        
        elif self.service == 'http':
            # Extract HTTP request data
            if 'url' in raw_data or 'path' in raw_data:
                return {
                    'url': raw_data.get('url', raw_data.get('path', '')),
                    'method': raw_data.get('method', 'GET'),
                    'session_data': {
                        'request_count': 1,
                        'failed_requests': 0,
                        'bytes_transferred': len(message)
                    }
                }
            elif 'HTTP request' in message:
                # Try to extract URL from message
                url_start = message.find('URL: ')
                if url_start != -1:
                    url = message[url_start + 5:].split()[0]
                    return {
                        'url': url,
                        'method': 'GET',
                        'session_data': {
                            'request_count': 1,
                            'failed_requests': 0,
                            'bytes_transferred': len(url)
                        }
                    }
        
        elif self.service == 'mysql':
            # Extract MySQL query data
            if 'query' in raw_data:
                return {
                    'query': raw_data['query'],
                    'session_data': {
                        'query_count': 1,
                        'failed_queries': 0,
                        'bytes_transferred': len(raw_data['query'])
                    }
                }
            elif 'MySQL query received' in message:
                # Try to extract query from message
                query_start = message.find('Query: ')
                if query_start != -1:
                    query = message[query_start + 7:]
                    return {
                        'query': query,
                        'session_data': {
                            'query_count': 1,
                            'failed_queries': 0,
                            'bytes_transferred': len(query)
                        }
                    }
        
        elif self.service == 'ftp':
            # Extract FTP command data
            if 'command' in raw_data:
                return {
                    'command': raw_data['command'],
                    'path': raw_data.get('path', ''),
                    'session_data': {
                        'read_ops': 1 if raw_data['command'].upper() in ['RETR', 'LIST', 'NLST'] else 0,
                        'write_ops': 1 if raw_data['command'].upper() in ['STOR', 'PUT'] else 0,
                        'delete_ops': 1 if raw_data['command'].upper() in ['DELE', 'RMD'] else 0,
                        'bytes_read': 0,
                        'bytes_written': 0,
                        'failed_ops': 0
                    }
                }
            elif 'FTP command' in message:
                # Try to extract command from message
                cmd_start = message.find('Command: ')
                if cmd_start != -1:
                    command = message[cmd_start + 9:].split()[0]
                    return {
                        'command': command,
                        'path': '',
                        'session_data': {
                            'read_ops': 1 if command.upper() in ['RETR', 'LIST', 'NLST'] else 0,
                            'write_ops': 1 if command.upper() in ['STOR', 'PUT'] else 0,
                            'delete_ops': 1 if command.upper() in ['DELE', 'RMD'] else 0,
                            'bytes_read': 0,
                            'bytes_written': 0,
                            'failed_ops': 0
                        }
                    }
        
        elif self.service == 'smb':
            # Extract SMB operation data
            if 'operation' in raw_data:
                return {
                    'operation': raw_data['operation'],
                    'path': raw_data.get('path', ''),
                    'session_data': {
                        'read_ops': 1 if raw_data['operation'].upper() in ['READ', 'QUERY_INFO', 'FIND'] else 0,
                        'write_ops': 1 if raw_data['operation'].upper() in ['WRITE', 'CREATE'] else 0,
                        'delete_ops': 1 if raw_data['operation'].upper() in ['DELETE'] else 0,
                        'bytes_read': 0,
                        'bytes_written': 0,
                        'failed_ops': 0
                    }
                }
            elif 'SMB command' in message:
                # Try to extract operation from message
                op_start = message.find('Operation: ')
                if op_start != -1:
                    operation = message[op_start + 11:].split()[0]
                    return {
                        'operation': operation,
                        'path': '',
                        'session_data': {
                            'read_ops': 1 if operation.upper() in ['READ', 'QUERY_INFO', 'FIND'] else 0,
                            'write_ops': 1 if operation.upper() in ['WRITE', 'CREATE'] else 0,
                            'delete_ops': 1 if operation.upper() in ['DELETE'] else 0,
                            'bytes_read': 0,
                            'bytes_written': 0,
                            'failed_ops': 0
                        }
                    }
        
        return None
    
    def get_ml_insights(self, conversations: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive ML insights from conversations"""
        if not self.ml_detector:
            return {'ml_available': False, 'message': 'ML analysis not available'}
        
        insights = {
            'ml_available': True,
            'service': self.service,
            'analysis_timestamp': datetime.datetime.now().isoformat(),
            'total_sessions': len(conversations),
            'anomalies': [],
            'risk_summary': {'high': 0, 'medium': 0, 'low': 0},
            'attack_patterns': {},
            'ml_metrics': {
                'entries_analyzed': 0,
                'anomalies_detected': 0,
                'avg_anomaly_score': 0.0,
                'max_anomaly_score': 0.0
            }
        }
        
        all_anomaly_scores = []
        
        # Analyze each conversation
        for session_id, conv in conversations.items():
            session_anomalies = []
            
            for entry in conv['entries']:
                ml_result = self.analyze_log_entry_ml(entry)
                insights['ml_metrics']['entries_analyzed'] += 1
                
                if ml_result and 'ml_anomaly_score' in ml_result:
                    anomaly_score = ml_result['ml_anomaly_score']
                    all_anomaly_scores.append(anomaly_score)
                    
                    # Consider entries with anomaly score > 0.7 as anomalies
                    if anomaly_score > 0.7:
                        risk_level = 'high' if anomaly_score > 0.9 else 'medium'
                        insights['risk_summary'][risk_level] += 1
                        insights['ml_metrics']['anomalies_detected'] += 1
                        
                        anomaly_data = {
                            'session_id': session_id,
                            'timestamp': entry.get('timestamp', ''),
                            'message': entry.get('message', '')[:100] + '...' if len(entry.get('message', '')) > 100 else entry.get('message', ''),
                            'anomaly_score': anomaly_score,
                            'risk_level': risk_level,
                            'ml_labels': ml_result.get('ml_labels', []),
                            'confidence': ml_result.get('ml_confidence', 0)
                        }
                        
                        session_anomalies.append(anomaly_data)
                        insights['anomalies'].append(anomaly_data)
                        
                        # Track attack patterns
                        for label in ml_result.get('ml_labels', []):
                            if label not in insights['attack_patterns']:
                                insights['attack_patterns'][label] = 0
                            insights['attack_patterns'][label] += 1
            
            # Add session-level insights
            conv['ml_anomalies'] = session_anomalies
            conv['ml_risk_score'] = max([a['anomaly_score'] for a in session_anomalies], default=0.0)
        
        # Calculate summary statistics
        if all_anomaly_scores:
            insights['ml_metrics']['avg_anomaly_score'] = sum(all_anomaly_scores) / len(all_anomaly_scores)
            insights['ml_metrics']['max_anomaly_score'] = max(all_anomaly_scores)
        
        # Sort anomalies by score (highest first)
        insights['anomalies'].sort(key=lambda x: x['anomaly_score'], reverse=True)
        
        # Limit to top 20 anomalies for display
        insights['anomalies'] = insights['anomalies'][:20]
        
        return insights
    
    def _format_user_input(self, entry: Dict[str, Any], timestamp: str) -> List[str]:
        """Format user input entries"""
        output = []
        if 'decoded_details' in entry:
            output.append(f"\n[{timestamp}] 👤 USER COMMAND:")
            output.append(f"   {entry['decoded_details']}")
        elif 'query' in entry['raw'] and entry['raw']['query']:
            output.append(f"\n[{timestamp}] 👤 SQL QUERY:")
            output.append(f"   {entry['raw']['query']}")
        elif 'command' in entry['raw'] and entry['raw']['command']:
            output.append(f"\n[{timestamp}] 👤 COMMAND:")
            output.append(f"   {entry['raw']['command']}")
        else:
            output.append(f"\n[{timestamp}] 👤 USER INPUT: {entry['message']}")
        return output
    
    def _format_ai_response(self, entry: Dict[str, Any], timestamp: str) -> List[str]:
        """Format AI response entries"""
        output = []
        message = entry['message']
        
        if 'decoded_details' in entry:
            output.append(f"\n[{timestamp}] 🤖 AI RESPONSE:")
            output.append(f"   {entry['decoded_details']}")
        elif 'LLM raw response' in message and 'llm_response' in entry['raw']:
            llm_response = entry['raw']['llm_response']
            if llm_response.startswith('```'):
                lines = llm_response.split('\n')
                if lines[0].strip().startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].strip() == '```':
                    lines = lines[:-1]
                llm_response = '\n'.join(lines)
            
            output.append(f"\n[{timestamp}] 🤖 AI RESPONSE:")
            for line in llm_response.split('\n'):
                output.append(f"   {line}")
        elif 'LLM raw response' in message:
            response_start = message.find("': ") + 3
            if response_start > 2:
                response = message[response_start:]
                output.append(f"\n[{timestamp}] 🤖 AI RESPONSE:")
                for line in response.split('\n'):
                    output.append(f"   {line}")
            else:
                output.append(f"\n[{timestamp}] 🤖 AI RESPONSE: {message}")
        else:
            output.append(f"\n[{timestamp}] 🤖 AI RESPONSE: {message}")
        return output
    
    def _format_entry(self, entry: Dict[str, Any]) -> List[str]:
        """Format a single log entry"""
        timestamp = entry['timestamp'][:19] if entry['timestamp'] else 'Unknown'
        message = entry['message']
        
        # Check entry type and format accordingly
        if any(keyword in message for keyword in ['User input', 'FTP command', 'HTTP request', 'MySQL query received']):
            return self._format_user_input(entry, timestamp)
        elif any(keyword in message for keyword in ['LLM response', 'LLM raw response', 'FTP response', 'HTTP response', 'MySQL response']):
            return self._format_ai_response(entry, timestamp)
        elif 'attack' in message.lower():
            output = [f"\n[{timestamp}] ⚠️ ATTACK: {message}"]
            if 'attack_types' in entry['raw']:
                output.append(f"   Types: {entry['raw']['attack_types']}")
            if 'severity' in entry['raw']:
                output.append(f"   Severity: {entry['raw']['severity']}")
            return output
        elif 'vulnerability exploitation attempt' in message.lower():
            output = [f"\n[{timestamp}] 🚨 CRITICAL: {message}"]
            if 'vulnerability_id' in entry['raw']:
                output.append(f"   Vulnerability: {entry['raw']['vulnerability_id']}")
            if 'cvss_score' in entry['raw']:
                output.append(f"   CVSS Score: {entry['raw']['cvss_score']}")
            return output
        elif entry['level'] in ['WARNING', 'ERROR', 'CRITICAL']:
            emoji = {'WARNING': '⚠️', 'ERROR': '❌', 'CRITICAL': '🚨'}.get(entry['level'], 'ℹ️')
            return [f"\n[{timestamp}] {emoji} {entry['level']}: {message}"]
        return []

    def format_conversation(self, conversations: Dict[str, Any], format_type: str = 'text',
                          show_full: bool = False, include_ml: bool = False) -> str:
        """Format conversations for display"""
        if format_type == 'json':
            # Add ML insights to JSON output if requested
            if include_ml:
                ml_insights = self.get_ml_insights(conversations)
                return json.dumps({
                    'conversations': conversations,
                    'ml_insights': ml_insights
                }, indent=2, default=str)
            return json.dumps(conversations, indent=2, default=str)
        
        output = []
        output.append("=" * 80)
        service_name = {"ssh": "SSH", "ftp": "FTP", "http": "HTTP", "mysql": "MySQL", "smb": "SMB"}.get(self.service, self.service.upper())
        output.append(f"NEXUS {service_name} HONEYPOT - SESSION CONVERSATIONS")
        if include_ml and self.ml_detector:
            output.append("🧠 ML-ENHANCED ANALYSIS ENABLED")
        output.append("=" * 80)
        
        # Add ML insights summary if requested
        if include_ml:
            ml_insights = self.get_ml_insights(conversations)
            if ml_insights.get('ml_available'):
                output.append("\n🧠 ML ANALYSIS SUMMARY:")
                output.append(f"   📊 Entries Analyzed: {ml_insights['ml_metrics']['entries_analyzed']}")
                output.append(f"   🚨 Anomalies Detected: {ml_insights['ml_metrics']['anomalies_detected']}")
                output.append(f"   📈 Avg Anomaly Score: {ml_insights['ml_metrics']['avg_anomaly_score']:.3f}")
                output.append(f"   ⚠️ Max Anomaly Score: {ml_insights['ml_metrics']['max_anomaly_score']:.3f}")
                
                # Risk summary
                risk_summary = ml_insights['risk_summary']
                output.append(f"   🔴 High Risk: {risk_summary['high']} | 🟡 Medium Risk: {risk_summary['medium']} | 🟢 Low Risk: {risk_summary['low']}")
                
                # Top attack patterns
                if ml_insights['attack_patterns']:
                    top_patterns = sorted(ml_insights['attack_patterns'].items(), key=lambda x: x[1], reverse=True)[:3]
                    patterns_str = ", ".join([f"{pattern} ({count})" for pattern, count in top_patterns])
                    output.append(f"   🎯 Top Attack Patterns: {patterns_str}")
                
                output.append("-" * 80)
        
        for session_id, conv in conversations.items():
            output.append(f"\n🖥️ SESSION: {session_id}")
            output.append(f"🌐 SOURCE IP: {conv['src_ip']}")
            output.append(f"📊 TOTAL ENTRIES: {len(conv['entries'])}")
            
            # Add ML risk score if available
            if include_ml and 'ml_risk_score' in conv:
                risk_score = conv['ml_risk_score']
                risk_emoji = "🔴" if risk_score > 0.9 else "🟡" if risk_score > 0.7 else "🟢"
                output.append(f"🧠 ML RISK SCORE: {risk_emoji} {risk_score:.3f}")
                
                # Show session anomalies count
                anomaly_count = len(conv.get('ml_anomalies', []))
                if anomaly_count > 0:
                    output.append(f"⚠️ ANOMALIES DETECTED: {anomaly_count}")
            
            output.append("-" * 60)
            
            if show_full:
                for entry in conv['entries']:
                    output.extend(self._format_entry(entry))
            else:
                commands = [e for e in conv['entries'] if any(keyword in e['message'] for keyword in ['User input', 'FTP command', 'HTTP request', 'MySQL query received'])]
                responses = [e for e in conv['entries'] if any(keyword in e['message'] for keyword in ['LLM response', 'LLM raw response', 'FTP response', 'HTTP response', 'MySQL response'])]
                attacks = [e for e in conv['entries'] if 'attack' in e['message'].lower() or 'vulnerability exploitation' in e['message'].lower()]
                
                output.append(f"   Commands: {len(commands)}")
                output.append(f"   Responses: {len(responses)}")
                output.append(f"   Attacks: {len(attacks)}")
        
        output.append("\n" + "=" * 80)
        return "\n".join(output)
    
    def save_conversation(self, content: str, output_file: str):
        """Save conversation to file with flexible path handling"""
        output_path = Path(output_file)
        
        # Convert relative paths to absolute from current working directory
        if not output_path.is_absolute():
            output_path = Path.cwd() / output_path
        
        # Create parent directories if they don't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(output_path.resolve())

def main():
    parser = argparse.ArgumentParser(description='NEXUS Honeypot Log Viewer with ML Analysis')
    parser.add_argument('service', choices=['ssh', 'ftp', 'http', 'mysql', 'smb'],
                       help='Service to view logs for')
    parser.add_argument('--log-file', '-f', help='Log file path')
    parser.add_argument('--session-id', '-i', help='Specific session ID')
    parser.add_argument('--decode', '-d', action='store_true', help='Decode base64 details')
    parser.add_argument('--conversation', '-c', action='store_true', help='Show full conversation')
    parser.add_argument('--save', '-s', help='Save to file')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--filter', choices=['all', 'commands', 'responses', 'attacks', 'anomalies'],
                       default='all', help='Filter entries')
    
    # ML Analysis options
    parser.add_argument('--ml-analysis', '--ml', action='store_true', 
                       help='Enable ML-based anomaly detection and analysis')
    parser.add_argument('--anomaly-threshold', type=float, default=0.7,
                       help='Anomaly detection threshold (0.0-1.0, default: 0.7)')
    parser.add_argument('--ml-insights', action='store_true',
                       help='Show detailed ML insights and statistics')
    parser.add_argument('--high-risk-only', action='store_true',
                       help='Show only high-risk sessions (anomaly score > 0.9)')
    
    args = parser.parse_args()
    
    if args.service not in ['ssh', 'ftp', 'http', 'mysql', 'smb']:
        print(f"Error: Log viewing for {args.service} not implemented")
        return 1
    
    # Default log file location - check both new and old locations
    if not args.log_file:
        base_dir = Path(__file__).parent.parent
        new_log_path = None
        old_log_path = None
        if args.service == 'ssh':
            new_log_path = base_dir / 'logs' / 'ssh_log.log'
            old_log_path = base_dir / 'service_emulators' / 'SSH' / 'ssh_log.log'
        elif args.service == 'ftp':
            new_log_path = base_dir / 'logs' / 'ftp_log.log'
            old_log_path = base_dir / 'service_emulators' / 'FTP' / 'ftp_log.log'
        elif args.service == 'http':
            new_log_path = base_dir / 'logs' / 'http_log.log'
            old_log_path = base_dir / 'service_emulators' / 'HTTP' / 'http_log.log'
        elif args.service == 'mysql':
            new_log_path = base_dir / 'logs' / 'mysql_log.log'
            old_log_path = base_dir / 'service_emulators' / 'MySQL' / 'mysql_log.log'
        elif args.service == 'smb':
            new_log_path = base_dir / 'logs' / 'smb_log.log'
            old_log_path = base_dir / 'service_emulators' / 'SMB' / 'smb_log.log'
        
        if new_log_path and new_log_path.exists():
            args.log_file = str(new_log_path)
        elif old_log_path and old_log_path.exists():
            args.log_file = str(old_log_path)
        elif new_log_path:
            args.log_file = str(new_log_path)  # Default to new location
    
    try:
        viewer = LogViewer(args.service)
        conversations = {}
        if args.service == 'ssh':
            conversations = viewer.parse_ssh_logs(
                args.log_file, args.session_id, args.decode, args.filter
            )
        elif args.service == 'ftp':
            conversations = viewer.parse_ftp_logs(
                args.log_file, args.session_id, args.decode, args.filter
            )
        elif args.service == 'http':
            conversations = viewer.parse_http_logs(
                args.log_file, args.session_id, args.decode, args.filter
            )
        elif args.service == 'mysql':
            conversations = viewer.parse_mysql_logs(
                args.log_file, args.session_id, args.decode, args.filter
            )
        elif args.service == 'smb':
            conversations = viewer.parse_smb_logs(
                args.log_file, args.session_id, args.decode, args.filter
            )
        
        if not conversations:
            print("No conversations found")
            return 1
        
        # Apply ML filtering if requested
        if args.ml_analysis or args.ml_insights:
            if not ML_AVAILABLE:
                print("❌ Error: ML analysis requested but ML components not available")
                return 1
            
            # Get ML insights first
            ml_insights = viewer.get_ml_insights(conversations)
            
            # Filter high-risk sessions if requested
            if args.high_risk_only:
                high_risk_sessions = {}
                for session_id, conv in conversations.items():
                    if conv.get('ml_risk_score', 0) > 0.9:
                        high_risk_sessions[session_id] = conv
                conversations = high_risk_sessions
                
                if not conversations:
                    print("No high-risk sessions found")
                    return 1
            
            # Filter anomalies if requested
            if args.filter == 'anomalies':
                anomaly_sessions = {}
                for session_id, conv in conversations.items():
                    if conv.get('ml_anomalies', []):
                        anomaly_sessions[session_id] = conv
                conversations = anomaly_sessions
                
                if not conversations:
                    print("No sessions with anomalies found")
                    return 1
            
            # Show detailed ML insights if requested
            if args.ml_insights:
                print("\n" + "=" * 80)
                print("🧠 DETAILED ML INSIGHTS")
                print("=" * 80)
                
                if ml_insights.get('ml_available'):
                    print(f"🔍 Service: {ml_insights['service'].upper()}")
                    print(f"📅 Analysis Time: {ml_insights['analysis_timestamp']}")
                    print(f"📊 Total Sessions: {ml_insights['total_sessions']}")
                    print(f"📈 Entries Analyzed: {ml_insights['ml_metrics']['entries_analyzed']}")
                    print(f"🚨 Anomalies Detected: {ml_insights['ml_metrics']['anomalies_detected']}")
                    print(f"📊 Average Anomaly Score: {ml_insights['ml_metrics']['avg_anomaly_score']:.3f}")
                    print(f"⚠️ Maximum Anomaly Score: {ml_insights['ml_metrics']['max_anomaly_score']:.3f}")
                    
                    # Risk breakdown
                    risk_summary = ml_insights['risk_summary']
                    print(f"\n🎯 RISK BREAKDOWN:")
                    print(f"   🔴 High Risk: {risk_summary['high']}")
                    print(f"   🟡 Medium Risk: {risk_summary['medium']}")
                    print(f"   🟢 Low Risk: {risk_summary['low']}")
                    
                    # Attack patterns
                    if ml_insights['attack_patterns']:
                        print(f"\n🎯 ATTACK PATTERNS DETECTED:")
                        for pattern, count in sorted(ml_insights['attack_patterns'].items(), key=lambda x: x[1], reverse=True):
                            print(f"   • {pattern}: {count} occurrences")
                    
                    # Top anomalies
                    if ml_insights['anomalies']:
                        print(f"\n🚨 TOP ANOMALIES:")
                        for i, anomaly in enumerate(ml_insights['anomalies'][:5], 1):
                            risk_emoji = "🔴" if anomaly['risk_level'] == 'high' else "🟡"
                            print(f"   {i}. {risk_emoji} Score: {anomaly['anomaly_score']:.3f} | Session: {anomaly['session_id']}")
                            print(f"      📝 {anomaly['message']}")
                            if anomaly['ml_labels']:
                                print(f"      🏷️ Labels: {', '.join(anomaly['ml_labels'])}")
                else:
                    print("❌ ML analysis not available")
                
                print("=" * 80)
        
        # Enable ML analysis in output if requested
        include_ml = args.ml_analysis or args.ml_insights
        output = viewer.format_conversation(conversations, args.format, args.conversation, include_ml)
        
        if args.save:
            saved_path = viewer.save_conversation(output, args.save)
            print(f"Conversation saved to: {saved_path}")
        else:
            # Handle encoding issues on Windows
            try:
                print(output)
            except UnicodeEncodeError:
                # Fallback to UTF-8 encoding
                import sys
                sys.stdout.buffer.write(output.encode('utf-8'))
                sys.stdout.buffer.write(b'\n')
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())