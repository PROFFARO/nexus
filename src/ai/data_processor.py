"""
Data Processing for NEXUS AI - Dataset loading, preprocessing, and feature preparation
"""

import json
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import logging
from datetime import datetime
import re

class DataProcessor:
    """Processes various honeypot datasets for ML training"""
    
    def __init__(self, datasets_dir: str = None):
        self.datasets_dir = Path(datasets_dir) if datasets_dir else Path(__file__).parent.parent.parent / "datasets"
        self.processed_data = {}
        
    def load_cowrie_logs(self, file_pattern: str = "cowrie.json.*") -> List[Dict[str, Any]]:
        """Load Cowrie SSH honeypot logs"""
        logs = []
        
        for log_file in self.datasets_dir.glob(file_pattern):
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue
                            
                logging.info(f"Loaded {len(logs)} entries from {log_file.name}")
                
            except Exception as e:
                logging.error(f"Failed to load {log_file}: {e}")
        
        return logs
    
    def load_ssh_anomaly_dataset(self) -> pd.DataFrame:
        """Load SSH anomaly detection dataset"""
        try:
            csv_file = self.datasets_dir / "ssh_anomaly_dataset.csv"
            if csv_file.exists():
                df = pd.read_csv(csv_file)
                logging.info(f"Loaded SSH anomaly dataset: {len(df)} rows")
                return df
        except Exception as e:
            logging.error(f"Failed to load SSH anomaly dataset: {e}")
        
        return pd.DataFrame()
    
    def load_network_intrusion_data(self) -> pd.DataFrame:
        """Load network intrusion detection datasets (CICIDS2017)"""
        datasets = []
        
        # Load all CICIDS2017 CSV files
        for csv_file in self.datasets_dir.glob("*.pcap_ISCX.csv"):
            try:
                # Try different encodings to handle encoding issues
                df = None
                for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                    try:
                        df = pd.read_csv(csv_file, encoding=encoding, low_memory=False)
                        break
                    except UnicodeDecodeError:
                        continue
                
                if df is None:
                    logging.error(f"Could not decode {csv_file} with any encoding")
                    continue
                
                # Clean column names (remove leading/trailing spaces)
                df.columns = df.columns.str.strip()
                
                # Standardize the label column name
                if 'Label' not in df.columns and ' Label' in df.columns:
                    df = df.rename(columns={' Label': 'Label'})
                
                df['source_file'] = csv_file.name
                datasets.append(df)
                logging.info(f"Loaded {csv_file.name}: {len(df)} rows")
            except Exception as e:
                logging.error(f"Failed to load {csv_file}: {e}")
        
        if datasets:
            combined_df = pd.concat(datasets, ignore_index=True)
            logging.info(f"Combined network intrusion data: {len(combined_df)} total rows")
            return combined_df
        
        return pd.DataFrame()
    
    def load_brute_force_data(self) -> List[Dict[str, Any]]:
        """Load brute force attack data"""
        try:
            json_file = self.datasets_dir / "brute_force_data.json"
            if json_file.exists():
                with open(json_file, 'r') as f:
                    data = json.load(f)
                logging.info(f"Loaded brute force data: {len(data)} entries")
                return data
        except Exception as e:
            logging.error(f"Failed to load brute force data: {e}")
        
        return []
    
    def process_ssh_data(self) -> List[Dict[str, Any]]:
        """Process SSH-related data for training"""
        processed_data = []
        
        # Process Cowrie logs
        cowrie_logs = self.load_cowrie_logs()
        for log in cowrie_logs:
            if log.get('eventid') == 'cowrie.command.input':
                processed_data.append({
                    'service': 'ssh',
                    'command': log.get('input', ''),
                    'src_ip': log.get('src_ip', ''),
                    'session': log.get('session', ''),
                    'timestamp': log.get('timestamp', ''),
                    'label': self._classify_ssh_command(log.get('input', '')),
                    'session_data': {
                        'duration': 0,  # Will be calculated from session data
                        'command_count': 1,
                        'failed_attempts': 0
                    }
                })
        
        # Process SSH anomaly dataset
        ssh_df = self.load_ssh_anomaly_dataset()
        if not ssh_df.empty:
            for _, row in ssh_df.iterrows():
                if row.get('event_type') == 'Command executed':
                    processed_data.append({
                        'service': 'ssh',
                        'command': row.get('detail', ''),
                        'src_ip': row.get('source_ip', ''),
                        'username': row.get('username', ''),
                        'timestamp': row.get('timestamp', ''),
                        'label': row.get('label', 'normal'),
                        'session_data': {
                            'duration': 0,
                            'command_count': 1,
                            'failed_attempts': 0
                        }
                    })
        
        logging.info(f"Processed {len(processed_data)} SSH data points")
        return processed_data
    
    def process_mysql_data(self) -> List[Dict[str, Any]]:
        """Process MySQL-related data for training"""
        processed_data = []
        
        # Process network data for database attacks
        network_df = self.load_network_intrusion_data()
        if not network_df.empty:
            # Filter for potential database attacks (port 3306, SQL injection patterns)
            db_attacks = network_df[
                (network_df['Destination Port'] == 3306) |
                network_df['Label'].str.contains('SQL', na=False)
            ]
            
            for _, row in db_attacks.iterrows():
                # Generate synthetic SQL queries based on attack patterns
                query = self._generate_synthetic_sql_query(row)
                
                processed_data.append({
                    'service': 'mysql',
                    'query': query,
                    'src_ip': row.get('Source IP', ''),
                    'dst_ip': row.get('Destination IP', ''),
                    'timestamp': datetime.now().isoformat(),
                    'label': self._normalize_label(row.get('Label', 'normal')),
                    'session_data': {
                        'query_count': 1,
                        'failed_queries': 0,
                        'bytes_transferred': row.get('Total Length of Fwd Packets', 0)
                    }
                })
        
        logging.info(f"Processed {len(processed_data)} MySQL data points")
        return processed_data
    
    def process_ftp_data(self) -> List[Dict[str, Any]]:
        """Process FTP-related data for training"""
        processed_data = []
        
        # Process network data for FTP attacks
        network_df = self.load_network_intrusion_data()
        if not network_df.empty:
            # Filter for FTP traffic (port 21)
            ftp_traffic = network_df[
                (network_df['Destination Port'] == 21) |
                (network_df['Source Port'] == 21)
            ]
            
            for _, row in ftp_traffic.iterrows():
                processed_data.append({
                    'service': 'ftp',
                    'command': self._generate_ftp_command(row),
                    'filename': f"file_{row.get('Flow ID', '')}.txt",
                    'src_ip': row.get('Source IP', ''),
                    'dst_ip': row.get('Destination IP', ''),
                    'timestamp': datetime.now().isoformat(),
                    'label': self._normalize_label(row.get('Label', 'normal')),
                    'session_data': {
                        'bytes_transferred': row.get('Total Length of Fwd Packets', 0),
                        'transfer_rate': row.get('Flow Bytes/s', 0),
                        'passive_mode': False,
                        'anonymous_login': True,
                        'failed_logins': 0,
                        'file_operations': 1,
                        'uploads': 0,
                        'downloads': 1
                    }
                })
        
        logging.info(f"Processed {len(processed_data)} FTP data points")
        return processed_data
    
    def _classify_ssh_command(self, command: str) -> str:
        """Classify SSH command as normal or malicious"""
        if not command:
            return 'normal'
        
        # Malicious patterns
        malicious_patterns = [
            r'rm\s+-rf\s+/',
            r'wget.*\.(sh|py|pl)',
            r'curl.*\|.*sh',
            r'nc\s+-l',
            r'python.*-c.*exec',
            r'perl.*-e',
            r'echo.*>.*\.ssh',
            r'cat\s+/etc/(passwd|shadow)',
            r'find.*-perm.*777',
            r'chmod.*777',
            r'sudo\s+su',
            r'history\s+-c'
        ]
        
        for pattern in malicious_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 'malicious'
        
        return 'normal'
    
    def _normalize_label(self, label: str) -> str:
        """Normalize attack labels to standard categories"""
        if not label:
            return 'normal'
        
        label_lower = label.lower().strip()
        if label_lower in ['benign', 'normal', 'legitimate']:
            return 'normal'
        
        if any(term in label_lower for term in ['ddos', 'dos']):
            return 'ddos'
        elif any(term in label_lower for term in ['brute', 'force']):
            return 'brute_force'
        elif any(term in label_lower for term in ['infiltration', 'infilteration']):
            return 'infiltration'
        elif any(term in label_lower for term in ['web', 'sql', 'xss']):
            return 'web_attack'
        elif any(term in label_lower for term in ['port', 'scan']):
            return 'port_scan'
        else:
            return 'malicious'
    
    def _generate_synthetic_sql_query(self, row: pd.Series) -> str:
        """Generate synthetic SQL query based on network flow data"""
        queries = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT * FROM users WHERE username = 'admin' AND password = 'admin'",
            "SELECT * FROM users WHERE 1=1",
            "INSERT INTO users (username, password) VALUES ('test', 'test')",
            "UPDATE users SET password = 'hacked' WHERE id = 1",
            "DELETE FROM users WHERE id > 0",
            "SHOW TABLES",
            "DESCRIBE users",
            "SELECT version()",
            "SELECT user()"
        ]
        
        # Choose query based on some flow characteristics
        flow_id = str(row.get('Flow ID', ''))
        query_idx = hash(flow_id) % len(queries)
        return queries[query_idx]
    
    def _generate_ftp_command(self, row: pd.Series) -> str:
        """Generate FTP command based on network flow data"""
        commands = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'DELE', 'MKD', 'RMD', 'PWD', 'CWD']
        flow_id = str(row.get('Flow ID', ''))
        cmd_idx = hash(flow_id) % len(commands)
        return commands[cmd_idx]
    
    def get_processed_data(self, service: str = None) -> Dict[str, List[Dict[str, Any]]]:
        """Get all processed data, optionally filtered by service"""
        if not self.processed_data:
            self.processed_data = {
                'ssh': self.process_ssh_data(),
                'mysql': self.process_mysql_data(),
                'ftp': self.process_ftp_data(),
            }
        
        if service:
            return {service: self.processed_data.get(service, [])}
        
        return self.processed_data
    
    def save_processed_data(self, output_dir: str = None):
        """Save processed data to files"""
        output_dir = Path(output_dir) if output_dir else self.datasets_dir.parent / "data"
        output_dir.mkdir(exist_ok=True)
        
        data = self.get_processed_data()
        
        for service, service_data in data.items():
            if service_data:
                output_file = output_dir / f"{service}_processed.json"
                with open(output_file, 'w') as f:
                    json.dump(service_data, f, indent=2)
                
                logging.info(f"Saved {len(service_data)} {service} records to {output_file}")
    
    def get_training_data(self, service: str, test_size: float = 0.2) -> Tuple[List[Dict], List[Dict]]:
        """Split data into training and testing sets"""
        data = self.get_processed_data(service)[service]
        
        if not data:
            return [], []
        
        # Shuffle data
        np.random.shuffle(data)
        
        # Split
        split_idx = int(len(data) * (1 - test_size))
        train_data = data[:split_idx]
        test_data = data[split_idx:]
        
        return train_data, test_data
