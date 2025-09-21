#!/usr/bin/env python3
"""
NEXUS Honeypot Log Viewer - Parse and display session conversations
"""

import json
import os
import argparse
from base64 import b64decode
from pathlib import Path
from typing import Dict, List, Any

class LogViewer:
    def __init__(self, service: str):
        self.service = service
        self.base_dir = Path(__file__).parent.parent
        
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
    
    def format_conversation(self, conversations: Dict[str, Any], format_type: str = 'text',
                          show_full: bool = False) -> str:
        """Format conversations for display"""
        if format_type == 'json':
            return json.dumps(conversations, indent=2, default=str)
        
        output = []
        output.append("=" * 80)
        service_name = {"ssh": "SSH", "ftp": "FTP", "http": "HTTP", "mysql": "MySQL"}.get(self.service, self.service.upper())
        output.append(f"NEXUS {service_name} HONEYPOT - SESSION CONVERSATIONS")
        output.append("=" * 80)
        
        for session_id, conv in conversations.items():
            output.append(f"\n🖥️ SESSION: {session_id}")
            output.append(f"🌐 SOURCE IP: {conv['src_ip']}")
            output.append(f"📊 TOTAL ENTRIES: {len(conv['entries'])}")
            output.append("-" * 60)
            
            if show_full:
                for entry in conv['entries']:
                    timestamp = entry['timestamp'][:19] if entry['timestamp'] else 'Unknown'
                    message = entry['message']
                    
                    if 'User input' in message or 'FTP command' in message or 'HTTP request' in message or 'MySQL query received' in message:
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
                            output.append(f"\n[{timestamp}] 👤 USER INPUT: {message}")
                    
                    elif 'LLM response' in message or 'LLM raw response' in message or 'FTP response' in message or 'HTTP response' in message or 'MySQL response' in message:
                        if 'decoded_details' in entry:
                            output.append(f"\n[{timestamp}] 🤖 AI RESPONSE:")
                            output.append(f"   {entry['decoded_details']}")
                        elif 'LLM raw response' in message and 'llm_response' in entry['raw']:
                            # Extract actual LLM response from log data
                            llm_response = entry['raw']['llm_response']
                            # Clean up markdown formatting
                            if llm_response.startswith('```'):
                                lines = llm_response.split('\n')
                                # Remove first and last lines if they contain ```
                                if lines[0].strip().startswith('```'):
                                    lines = lines[1:]
                                if lines and lines[-1].strip() == '```':
                                    lines = lines[:-1]
                                llm_response = '\n'.join(lines)
                            
                            output.append(f"\n[{timestamp}] 🤖 AI RESPONSE:")
                            # Format multi-line responses properly
                            for line in llm_response.split('\n'):
                                output.append(f"   {line}")
                        elif 'LLM raw response' in message:
                            # Fallback: Extract complete LLM response from message
                            response_start = message.find("': ") + 3
                            if response_start > 2:
                                response = message[response_start:]
                                output.append(f"\n[{timestamp}] 🤖 AI RESPONSE:")
                                # Format multi-line responses properly
                                for line in response.split('\n'):
                                    output.append(f"   {line}")
                            else:
                                output.append(f"\n[{timestamp}] 🤖 AI RESPONSE: {message}")
                        else:
                            output.append(f"\n[{timestamp}] 🤖 AI RESPONSE: {message}")
                    
                    elif 'attack' in message.lower():
                        output.append(f"\n[{timestamp}] ⚠️ ATTACK: {message}")
                        if 'attack_types' in entry['raw']:
                            output.append(f"   Types: {entry['raw']['attack_types']}")
                        if 'severity' in entry['raw']:
                            output.append(f"   Severity: {entry['raw']['severity']}")
                    
                    elif 'vulnerability exploitation attempt' in message.lower():
                        output.append(f"\n[{timestamp}] 🚨 CRITICAL: {message}")
                        if 'vulnerability_id' in entry['raw']:
                            output.append(f"   Vulnerability: {entry['raw']['vulnerability_id']}")
                        if 'cvss_score' in entry['raw']:
                            output.append(f"   CVSS Score: {entry['raw']['cvss_score']}")
                    
                    elif entry['level'] in ['WARNING', 'ERROR', 'CRITICAL']:
                        emoji = {'WARNING': '⚠️', 'ERROR': '❌', 'CRITICAL': '🚨'}.get(entry['level'], 'ℹ️')
                        output.append(f"\n[{timestamp}] {emoji} {entry['level']}: {message}")
            else:
                commands = [e for e in conv['entries'] if 'User input' in e['message'] or 'FTP command' in e['message'] or 'HTTP request' in e['message'] or 'MySQL query received' in e['message']]
                responses = [e for e in conv['entries'] if 'LLM response' in e['message'] or 'LLM raw response' in e['message'] or 'FTP response' in e['message'] or 'HTTP response' in e['message'] or 'MySQL response' in e['message']]
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
    parser = argparse.ArgumentParser(description='NEXUS Honeypot Log Viewer')
    parser.add_argument('service', choices=['ssh', 'ftp', 'http', 'mysql', 'smb'],
                       help='Service to view logs for')
    parser.add_argument('--log-file', '-f', help='Log file path')
    parser.add_argument('--session-id', '-i', help='Specific session ID')
    parser.add_argument('--decode', '-d', action='store_true', help='Decode base64 details')
    parser.add_argument('--conversation', '-c', action='store_true', help='Show full conversation')
    parser.add_argument('--save', '-s', help='Save to file')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--filter', choices=['all', 'commands', 'responses', 'attacks'],
                       default='all', help='Filter entries')
    
    args = parser.parse_args()
    
    if args.service not in ['ssh', 'ftp', 'http', 'mysql']:
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
        
        if not conversations:
            print("No conversations found")
            return 1
        
        output = viewer.format_conversation(conversations, args.format, args.conversation)
        
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