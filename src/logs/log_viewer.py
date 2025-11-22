#!/usr/bin/env python3
"""
NEXUS Honeypot Log Viewer - Comprehensive protocol analysis with command timelines,
session summaries, attack detection, ML anomaly detection, and detailed protocol specifics

Supports: SSH, FTP, HTTP, MySQL, SMB
Features: Command/request timelines, session summaries, protocol details, attack analysis,
ML-based anomaly detection, text and JSON output formats
"""

import json
import os
import sys
import argparse
import datetime
from base64 import b64decode
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict

# Import ML components
try:
    sys.path.append(str(Path(__file__).parent.parent))
    from ai.detectors import MLDetector
    from ai.config import MLConfig
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    MLDetector = None
    MLConfig = None


class ProtocolAnalyzer:
    """Base class for protocol-specific analysis"""
    
    def __init__(self, service: str):
        self.service = service
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract protocol-specific details from log entry"""
        return {}
    
    def categorize_entry(self, message: str, log_entry: Dict[str, Any]) -> str:
        """Categorize log entry (command, response, attack, other)"""
        if 'attack' in message.lower():
            return 'attack'
        elif 'command' in message.lower() or 'User input' in message:
            return 'command'
        elif 'response' in message.lower() or 'LLM response' in message:
            return 'response'
        return 'other'
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format protocol-specific command details"""
        return ""


class SSHAnalyzer(ProtocolAnalyzer):
    """SSH Protocol specific analyzer"""
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SSH-specific details"""
        details = {
            'username': log_entry.get('username', 'unknown'),
            'command': log_entry.get('command', ''),
            'src_port': log_entry.get('src_port'),
            'dst_port': log_entry.get('dst_port'),
            'interactive': log_entry.get('interactive', False),
        }
        
        # Attack details
        if 'attack_types' in log_entry:
            details['attack_types'] = log_entry['attack_types']
            details['severity'] = log_entry.get('severity', 'unknown')
            details['indicators'] = log_entry.get('indicators', [])
        
        # Threat intelligence
        if 'threat_signatures_loaded' in log_entry:
            details['threat_signatures'] = log_entry.get('threat_signatures_loaded', 0)
            details['attack_patterns'] = log_entry.get('attack_patterns_loaded', 0)
        
        # Geolocation & Reputation
        if 'geolocation' in log_entry:
            details['geolocation'] = log_entry['geolocation']
            details['reputation'] = log_entry.get('reputation', {})
            details['ai_features'] = log_entry.get('ai_features_enabled', {})
        
        return details
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format SSH command details"""
        pd = entry.get('protocol_details', {})
        cmd = pd.get('command', 'N/A')
        user = pd.get('username', 'unknown')
        return f"  {user}@localhost: {cmd}"


class FTPAnalyzer(ProtocolAnalyzer):
    """FTP Protocol specific analyzer"""
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract FTP-specific details"""
        details = {
            'username': log_entry.get('username', 'anonymous'),
            'command': log_entry.get('command', ''),
            'path': log_entry.get('path', ''),
            'src_port': log_entry.get('src_port'),
            'dst_port': log_entry.get('dst_port'),
        }
        
        if 'attack_types' in log_entry:
            details['attack_types'] = log_entry['attack_types']
            details['severity'] = log_entry.get('severity', 'unknown')
        
        return details
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format FTP command details"""
        pd = entry.get('protocol_details', {})
        cmd = pd.get('command', 'N/A')
        path = pd.get('path', '')
        return f"  FTP {cmd} {path}"


class HTTPAnalyzer(ProtocolAnalyzer):
    """HTTP Protocol specific analyzer"""
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract HTTP-specific details"""
        details = {
            'method': log_entry.get('method', 'GET'),
            'path': log_entry.get('path', '/'),
            'url': log_entry.get('url', ''),
            'status_code': log_entry.get('status_code'),
            'user_agent': log_entry.get('user_agent', ''),
            'src_port': log_entry.get('src_port'),
            'dst_port': log_entry.get('dst_port'),
        }
        
        if 'attack_types' in log_entry:
            details['attack_types'] = log_entry['attack_types']
            details['severity'] = log_entry.get('severity', 'unknown')
            details['indicators'] = log_entry.get('indicators', [])
        
        return details
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format HTTP request details"""
        pd = entry.get('protocol_details', {})
        method = pd.get('method', 'GET')
        path = pd.get('path', '/')
        status = pd.get('status_code', '?')
        return f"  {method} {path} ({status})"


class MySQLAnalyzer(ProtocolAnalyzer):
    """MySQL Protocol specific analyzer"""
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract MySQL-specific details"""
        details = {
            'username': log_entry.get('username', 'unknown'),
            'query': log_entry.get('query', ''),
            'database': log_entry.get('database', ''),
            'client_ip': log_entry.get('client_ip', log_entry.get('src_ip', 'unknown')),
            'src_port': log_entry.get('src_port'),
            'dst_port': log_entry.get('dst_port'),
        }
        
        if 'attack_types' in log_entry:
            details['attack_types'] = log_entry['attack_types']
            details['severity'] = log_entry.get('severity', 'unknown')
            details['indicators'] = log_entry.get('indicators', [])
        
        return details
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format MySQL query details"""
        pd = entry.get('protocol_details', {})
        query = pd.get('query', 'N/A')
        query_short = (query[:60] + '...') if len(query) > 60 else query
        return f"  {query_short}"


class SMBAnalyzer(ProtocolAnalyzer):
    """SMB Protocol specific analyzer"""
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SMB-specific details"""
        details = {
            'username': log_entry.get('username', 'unknown'),
            'operation': log_entry.get('operation', ''),
            'path': log_entry.get('path', ''),
            'share': log_entry.get('share', ''),
            'src_port': log_entry.get('src_port'),
            'dst_port': log_entry.get('dst_port'),
        }
        
        if 'attack_types' in log_entry:
            details['attack_types'] = log_entry['attack_types']
            details['severity'] = log_entry.get('severity', 'unknown')
        
        return details
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format SMB operation details"""
        pd = entry.get('protocol_details', {})
        op = pd.get('operation', 'N/A')
        path = pd.get('path', '')
        return f"  {op} {path}"


class SessionReader:
    """Helper class to read session data from session directories"""
    
    def __init__(self, base_dir: Optional[Path] = None):
        """Initialize SessionReader with optional base directory"""
        self.base_dir = base_dir or Path(__file__).parent.parent
    
    def get_session_directories(self, service: str) -> List[Path]:
        """Get session directories for a specific service"""
        try:
            session_base = self.base_dir / 'sessions' / service
            if session_base.exists():
                return [d for d in session_base.iterdir() if d.is_dir()]
        except Exception:
            pass
        return []
    
    def read_session_summary(self, session_dir: Path) -> Optional[Dict[str, Any]]:
        """Read session summary JSON if available"""
        try:
            summary_file = session_dir / 'summary.json'
            if summary_file.exists():
                with open(summary_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return None
    
    def read_session_replay(self, replay_file: str) -> Optional[Dict[str, Any]]:
        """Read session replay JSON if available"""
        try:
            with open(replay_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
        return None 


class LogViewer:
    """Unified log viewer supporting all protocols"""
    
    ANALYZERS = {
        'ssh': SSHAnalyzer,
        'ftp': FTPAnalyzer,
        'http': HTTPAnalyzer,
        'mysql': MySQLAnalyzer,
        'smb': SMBAnalyzer,
    }
    
    def __init__(self, service: str):
        self.service = service
        self.base_dir = Path(__file__).parent.parent
        self.session_reader = SessionReader(self.base_dir)
        self.analyzer = self.ANALYZERS.get(service, ProtocolAnalyzer)(service)
        
        # Initialize ML detector if available
        self.ml_detector = None
        if ML_AVAILABLE and MLDetector and MLConfig:
            try:
                ml_config = MLConfig(service)
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector(service, ml_config)
            except Exception:
                pass
        
    def parse_logs(self, log_file: str, session_id: str = "", decode: bool = False,
                   filter_type: str = 'all') -> Dict[str, Any]:
        """Universal log parser - supports all protocols"""
        conversations = {}
        
        if not os.path.exists(log_file):
            return {}
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    task_name = log_entry.get('task_name', 'unknown')
                    message = log_entry.get('message', '')
                    
                    if session_id and session_id not in task_name:
                        continue
                    
                    # Initialize session
                    if task_name not in conversations:
                        conversations[task_name] = {
                            'session_id': task_name,
                            'src_ip': log_entry.get('src_ip', 'unknown'),
                            'dst_ip': log_entry.get('dst_ip', 'unknown'),
                            'src_port': log_entry.get('src_port'),
                            'dst_port': log_entry.get('dst_port'),
                            'protocol_details': {},
                            'entries': [],
                            'commands': [],
                            'responses': [],
                            'attacks': [],
                            'statistics': {
                                'total_entries': 0,
                                'total_commands': 0,
                                'total_responses': 0,
                                'total_attacks': 0,
                            }
                        }
                    
                    # Extract protocol-specific details
                    protocol_details = self.analyzer.extract_protocol_details(log_entry)
                    
                    # Build entry
                    entry = {
                        'timestamp': log_entry.get('timestamp', ''),
                        'message': message,
                        'level': log_entry.get('level', 'INFO'),
                        'raw': log_entry,
                        'protocol_details': protocol_details,
                    }
                    
                    # Decode base64 if requested
                    if decode and 'details' in log_entry:
                        try:
                            decoded = b64decode(log_entry['details']).decode('utf-8')
                            entry['decoded_details'] = decoded
                        except:
                            entry['decoded_details'] = 'Failed to decode'
                    
                    # Categorize entry
                    category = self.analyzer.categorize_entry(message, log_entry)
                    
                    if category == 'command':
                        conversations[task_name]['commands'].append(entry)
                    elif category == 'response':
                        conversations[task_name]['responses'].append(entry)
                    elif category == 'attack':
                        conversations[task_name]['attacks'].append(entry)
                    
                    conversations[task_name]['entries'].append(entry)
                    
                    # Update session-level details
                    if 'username' in protocol_details and 'username' not in conversations[task_name]['protocol_details']:
                        conversations[task_name]['protocol_details']['username'] = protocol_details['username']
                    
                except (json.JSONDecodeError, Exception):
                    continue
        
        # Calculate statistics
        for task_name, conv in conversations.items():
            conv['statistics']['total_entries'] = len(conv['entries'])
            conv['statistics']['total_commands'] = len(conv['commands'])
            conv['statistics']['total_responses'] = len(conv['responses'])
            conv['statistics']['total_attacks'] = len(conv['attacks'])
        
        return conversations
    
    def parse_ssh_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                      filter_type: str = 'all') -> Dict[str, Any]:
        """Parse SSH logs (backward compatibility)"""
        return self.parse_logs(log_file, session_id, decode, filter_type)
    
    def parse_ftp_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                      filter_type: str = 'all') -> Dict[str, Any]:
        """Parse FTP logs (backward compatibility)"""
        return self.parse_logs(log_file, session_id, decode, filter_type)
    
    def parse_http_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                       filter_type: str = 'all') -> Dict[str, Any]:
        """Parse HTTP logs (backward compatibility)"""
        return self.parse_logs(log_file, session_id, decode, filter_type)
    
    def parse_mysql_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                        filter_type: str = 'all') -> Dict[str, Any]:
        """Parse MySQL logs (backward compatibility)"""
        return self.parse_logs(log_file, session_id, decode, filter_type)
    
    def parse_smb_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                      filter_type: str = 'all') -> Dict[str, Any]:
        """Parse SMB logs (backward compatibility)"""
        return self.parse_logs(log_file, session_id, decode, filter_type)
    
    def get_ml_insights(self, conversations: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ML insights from conversations"""
        if not self.ml_detector:
            return {'ml_available': False}
        
        insights = {
            'ml_available': True,
            'service': self.service,
            'timestamp': datetime.datetime.now().isoformat(),
            'total_sessions': len(conversations),
            'anomalies': [],
            'risk_summary': {'high': 0, 'medium': 0, 'low': 0},
            'metrics': {
                'entries_analyzed': 0,
                'anomalies_detected': 0,
            }
        }
        
        for session_id, conv in conversations.items():
            for entry in conv['entries']:
                insights['metrics']['entries_analyzed'] += 1
                ml_result = self.analyze_log_entry_ml(entry)
                
                if ml_result and 'ml_anomaly_score' in ml_result:
                    anomaly_score = ml_result['ml_anomaly_score']
                    if anomaly_score > 0.7:
                        risk_level = 'high' if anomaly_score > 0.9 else 'medium'
                        insights['risk_summary'][risk_level] += 1
                        insights['metrics']['anomalies_detected'] += 1
        
        return insights
    
    def analyze_log_entry_ml(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze single log entry with ML"""
        if not self.ml_detector:
            return {}
        try:
            ml_data = self._extract_ml_features(entry)
            if not ml_data:
                return {}
            return self.ml_detector.score(ml_data)
        except Exception:
            return {}
    
    def _extract_ml_features(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract ML features from entry"""
        pd = entry.get('protocol_details', {})
        
        if self.service == 'ssh':
            cmd = pd.get('command', '')
            return {'command': cmd} if cmd else None
        elif self.service == 'http':
            path = pd.get('path', '/')
            return {'method': pd.get('method', 'GET'), 'path': path} if path else None
        elif self.service == 'mysql':
            query = pd.get('query', '')
            return {'query': query} if query else None
        elif self.service == 'ftp':
            cmd = pd.get('command', '')
            return {'command': cmd, 'path': pd.get('path', '')} if cmd else None
        elif self.service == 'smb':
            op = pd.get('operation', '')
            return {'operation': op, 'path': pd.get('path', '')} if op else None
        
        return None
    
    def format_text(self, conversations: Dict[str, Any], include_ml: bool = False,
                   show_full: bool = False) -> str:
        """Format as human-readable text"""
        output = []
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        output.append("=" * 120)
        output.append(f"NEXUS {self.service.upper()} HONEYPOT - COMPREHENSIVE SESSION ANALYSIS")
        output.append(f"Generated: {timestamp}")
        output.append("=" * 120)
        
        # System details
        output.append("\nSYSTEM DETAILS:")
        output.append(f"  Service Protocol: {self.service.upper()}")
        output.append(f"  Total Sessions: {len(conversations)}")
        total_entries = sum(len(c['entries']) for c in conversations.values())
        output.append(f"  Total Entries: {total_entries}")
        total_commands = sum(len(c['commands']) for c in conversations.values())
        total_responses = sum(len(c['responses']) for c in conversations.values())
        total_attacks = sum(len(c['attacks']) for c in conversations.values())
        output.append(f"  Commands: {total_commands} | Responses: {total_responses} | Attacks: {total_attacks}")
        
        # ML details if enabled
        if include_ml and self.ml_detector:
            output.append("\nML ANALYSIS ENABLED:")
            output.append(f"  Detector: {self.service.upper()} ML Detector")
            ml_insights = self.get_ml_insights(conversations)
            if ml_insights.get('ml_available'):
                metrics = ml_insights.get('metrics', {})
                risk = ml_insights.get('risk_summary', {})
                output.append(f"  Entries Analyzed: {metrics.get('entries_analyzed', 0)}")
                output.append(f"  Anomalies Detected: {metrics.get('anomalies_detected', 0)}")
                output.append(f"  Risk: High={risk.get('high', 0)} | Medium={risk.get('medium', 0)} | Low={risk.get('low', 0)}")
        
        output.append("\n" + "=" * 120)
        
        # Session details
        for idx, (session_id, conv) in enumerate(conversations.items(), 1):
            output.append(f"\n[SESSION {idx}] {session_id}")
            output.append("-" * 120)
            
            # Connection details
            src = conv['src_ip']
            src_port = conv.get('src_port', '?')
            dst = conv['dst_ip']
            dst_port = conv.get('dst_port', '?')
            output.append(f"  Connection: {src}:{src_port} -> {dst}:{dst_port}")
            
            # Protocol details
            if conv['protocol_details']:
                output.append(f"  Protocol Details:")
                for key, value in conv['protocol_details'].items():
                    if isinstance(value, (dict, list)):
                        output.append(f"    {key}: {json.dumps(value, default=str)[:70]}")
                    else:
                        output.append(f"    {key}: {value}")
            
            # Statistics
            stats = conv['statistics']
            output.append(f"  Statistics: {stats['total_entries']} entries | {stats['total_commands']} commands | {stats['total_responses']} responses | {stats['total_attacks']} attacks")
            
            # Command timeline
            if conv['commands']:
                output.append(f"\n  COMMAND TIMELINE ({len(conv['commands'])} total):")
                for i, cmd in enumerate(conv['commands'], 1):
                    ts = cmd.get('timestamp', '')[:19]
                    details = self.analyzer.format_command_details(cmd)
                    is_attack = cmd.get('message', '').lower()
                    output.append(f"    {i}. [{ts}]{details}")
            
            # Responses
            if conv['responses']:
                output.append(f"\n  RESPONSES ({len(conv['responses'])} total):")
                for i, resp in enumerate(conv['responses'][:5], 1):  # Show first 5
                    ts = resp.get('timestamp', '')[:19]
                    msg = resp.get('message', '')[:70]
                    output.append(f"    {i}. [{ts}] {msg}")
                if len(conv['responses']) > 5:
                    output.append(f"    ... and {len(conv['responses']) - 5} more")
            
            # Attacks
            if conv['attacks']:
                output.append(f"\n  DETECTED ATTACKS ({len(conv['attacks'])} total):")
                for i, attack in enumerate(conv['attacks'], 1):
                    ts = attack.get('timestamp', '')[:19]
                    msg = attack.get('message', '')[:70]
                    raw = attack.get('raw', {})
                    types = raw.get('attack_types', [])
                    severity = raw.get('severity', 'unknown')
                    output.append(f"    {i}. [{ts}] {msg}")
                    if types:
                        output.append(f"       Types: {', '.join(types)} | Severity: {severity}")
            
            output.append("-" * 120)
        
        output.append("\n" + "=" * 120)
        return "\n".join(output)
    
    def format_json(self, conversations: Dict[str, Any], include_ml: bool = False) -> str:
        """Format as JSON"""
        data = {
            'service': self.service,
            'timestamp': datetime.datetime.now().isoformat(),
            'summary': {
                'total_sessions': len(conversations),
                'total_entries': sum(len(c['entries']) for c in conversations.values()),
                'total_commands': sum(len(c['commands']) for c in conversations.values()),
                'total_responses': sum(len(c['responses']) for c in conversations.values()),
                'total_attacks': sum(len(c['attacks']) for c in conversations.values()),
            },
            'sessions': {}
        }
        
        for session_id, conv in conversations.items():
            session_data = {
                'session_id': session_id,
                'source': {
                    'ip': conv['src_ip'],
                    'port': conv.get('src_port'),
                },
                'destination': {
                    'ip': conv['dst_ip'],
                    'port': conv.get('dst_port'),
                },
                'protocol_details': conv['protocol_details'],
                'statistics': conv['statistics'],
                'entries': [
                    {
                        'timestamp': e['timestamp'],
                        'message': e['message'],
                        'level': e['level'],
                        'protocol_details': e['protocol_details'],
                        'decoded_details': e.get('decoded_details'),
                    }
                    for e in conv['entries']
                ],
                'commands': len(conv['commands']),
                'responses': len(conv['responses']),
                'attacks': [
                    {
                        'timestamp': a.get('timestamp'),
                        'message': a.get('message'),
                        'attack_types': a.get('raw', {}).get('attack_types', []),
                        'severity': a.get('raw', {}).get('severity'),
                        'indicators': a.get('raw', {}).get('indicators', [])[:3],
                    }
                    for a in conv['attacks']
                ]
            }
            
            if include_ml:
                ml_insights = self.get_ml_insights({session_id: conv})
                session_data['ml_insights'] = ml_insights
            
            data['sessions'][session_id] = session_data
        
        if include_ml:
            data['ml_summary'] = self.get_ml_insights(conversations)
        
        return json.dumps(data, indent=2, default=str)
    
    def format_conversation(self, conversations: Dict[str, Any], format_type: str = 'text',
                          show_full: bool = False, include_ml: bool = False) -> str:
        """Format conversations (backward compatibility)"""
        if format_type == 'json':
            return self.format_json(conversations, include_ml)
        else:
            return self.format_text(conversations, include_ml, show_full)
    
    def save_conversation(self, content: str, output_file: str) -> str:
        """Save to file"""
        output_path = Path(output_file)
        
        if not output_path.is_absolute():
            output_path = Path.cwd() / output_path
        
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
                print(" Error: ML analysis requested but ML components not available")
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
                print(" DETAILED ML INSIGHTS")
                print("=" * 80)
                
                if ml_insights.get('ml_available'):
                    print(f" Service: {ml_insights['service'].upper()}")
                    print(f" Analysis Time: {ml_insights['analysis_timestamp']}")
                    print(f" Total Sessions: {ml_insights['total_sessions']}")
                    print(f" Entries Analyzed: {ml_insights['ml_metrics']['entries_analyzed']}")
                    print(f" Anomalies Detected: {ml_insights['ml_metrics']['anomalies_detected']}")
                    print(f" Average Anomaly Score: {ml_insights['ml_metrics']['avg_anomaly_score']:.3f}")
                    print(f" Maximum Anomaly Score: {ml_insights['ml_metrics']['max_anomaly_score']:.3f}")
                    
                    # Risk breakdown
                    risk_summary = ml_insights['risk_summary']
                    print(f"\n RISK BREAKDOWN:")
                    print(f"    High Risk: {risk_summary['high']}")
                    print(f"    Medium Risk: {risk_summary['medium']}")
                    print(f"    Low Risk: {risk_summary['low']}")
                    
                    # Attack patterns
                    if ml_insights['attack_patterns']:
                        print(f"\n ATTACK PATTERNS DETECTED:")
                        for pattern, count in sorted(ml_insights['attack_patterns'].items(), key=lambda x: x[1], reverse=True):
                            print(f"   • {pattern}: {count} occurrences")
                    
                    # Top anomalies
                    if ml_insights['anomalies']:
                        print(f"\n TOP ANOMALIES:")
                        for i, anomaly in enumerate(ml_insights['anomalies'][:5], 1):
                            risk_emoji = "High" if anomaly['risk_level'] == 'high' else "Low"
                            print(f"   {i}. {risk_emoji} Score: {anomaly['anomaly_score']:.3f} | Session: {anomaly['session_id']}")
                            print(f"       {anomaly['message']}")
                            if anomaly['ml_labels']:
                                print(f"      Labels: {', '.join(anomaly['ml_labels'])}")
                else:
                    print(" ML analysis not available")
                
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