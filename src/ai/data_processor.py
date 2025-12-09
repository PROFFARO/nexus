"""
Data Processing for NEXUS AI - Dataset loading, preprocessing, and feature preparation
With comprehensive logging and verbose output for ML operations.
"""

import json
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
import logging
from datetime import datetime
import re
import time
import os

# Import ML Logger
try:
    from .ml_logger import get_ml_logger, VerbosityLevel
except ImportError:
    from ml_logger import get_ml_logger, VerbosityLevel


class DataProcessor:
    """Processes various honeypot datasets for ML training with detailed logging"""
    
    def __init__(self, datasets_dir: str = None):
        self.datasets_dir = Path(datasets_dir) if datasets_dir else Path(__file__).parent.parent.parent / "datasets"
        self.processed_data = {}
        self.verbosity = VerbosityLevel.NORMAL
        self.ml_logger = None
        self._file_stats = {}  # Track file loading statistics
        
    def set_verbosity(self, level: int):
        """Set verbosity level for logging"""
        self.verbosity = level
        self.ml_logger = get_ml_logger(level)
        
    def _get_logger(self):
        """Get ML logger instance"""
        if self.ml_logger is None:
            self.ml_logger = get_ml_logger(self.verbosity)
        return self.ml_logger
        
    def load_cowrie_logs(self, file_pattern: str = "cowrie.json.*") -> List[Dict[str, Any]]:
        """Load Cowrie SSH honeypot logs with detailed progress"""
        logs = []
        logger = self._get_logger()
        
        # Get list of files to process
        log_files = sorted(self.datasets_dir.glob(file_pattern))
        total_files = len(log_files)
        
        if total_files == 0:
            logger.log_warning(f"No files matching pattern '{file_pattern}' in {self.datasets_dir}")
            return logs
            
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Loading Cowrie logs from {total_files} files...", level="info")
        
        cumulative_entries = 0
        load_start = time.time()
        
        for file_idx, log_file in enumerate(log_files):
            file_start = time.time()
            file_entries = 0
            file_errors = 0
            
            try:
                file_size = log_file.stat().st_size
                
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f):
                        try:
                            log_entry = json.loads(line.strip())
                            logs.append(log_entry)
                            file_entries += 1
                        except json.JSONDecodeError:
                            file_errors += 1
                            continue
                
                cumulative_entries = len(logs)
                file_time = time.time() - file_start
                
                # Store file statistics
                self._file_stats[log_file.name] = {
                    'entries': file_entries,
                    'errors': file_errors,
                    'size': file_size,
                    'time': file_time
                }
                
                # Log file loading with progress
                if self.verbosity >= VerbosityLevel.VERBOSE:
                    logger.log_file_loaded(
                        log_file.name, 
                        cumulative_entries, 
                        size_bytes=file_size,
                        cumulative=cumulative_entries
                    )
                
                logging.info(f"Loaded {cumulative_entries} entries from {log_file.name}")
                
            except Exception as e:
                logger.log_error(f"Failed to load {log_file.name}", exception=e)
                logging.error(f"Failed to load {log_file}: {e}")
        
        total_time = time.time() - load_start
        
        # Summary statistics
        if self.verbosity >= VerbosityLevel.NORMAL:
            total_errors = sum(stats.get('errors', 0) for stats in self._file_stats.values())
            total_size = sum(stats.get('size', 0) for stats in self._file_stats.values())
            
            logger.log_step(
                f"Loaded {len(logs):,} Cowrie entries from {total_files} files "
                f"({total_size / 1024 / 1024:.1f} MB) in {total_time:.2f}s",
                level="success"
            )
            
            if total_errors > 0 and self.verbosity >= VerbosityLevel.DEBUG:
                logger.log_step(f"Skipped {total_errors:,} malformed entries", level="warning")
        
        return logs
    
    def load_ssh_anomaly_dataset(self) -> pd.DataFrame:
        """Load SSH anomaly detection dataset with detailed logging"""
        logger = self._get_logger()
        
        try:
            csv_file = self.datasets_dir / "ssh_anomaly_dataset.csv"
            
            if not csv_file.exists():
                if self.verbosity >= VerbosityLevel.DEBUG:
                    logger.log_step(f"SSH anomaly dataset not found at {csv_file}", level="debug")
                return pd.DataFrame()
            
            load_start = time.time()
            file_size = csv_file.stat().st_size
            
            if self.verbosity >= VerbosityLevel.VERBOSE:
                logger.log_step(f"Loading SSH anomaly dataset...", level="info")
            
            df = pd.read_csv(csv_file)
            load_time = time.time() - load_start
            
            # Log detailed statistics
            if self.verbosity >= VerbosityLevel.VERBOSE:
                logger.log_data_stats(df, "SSH Anomaly Dataset")
                logger.log_step(
                    f"Columns: {', '.join(df.columns[:5])}{'...' if len(df.columns) > 5 else ''}",
                    level="debug"
                )
            
            logging.info(f"Loaded SSH anomaly dataset: {len(df)} rows")
            
            if self.verbosity >= VerbosityLevel.NORMAL:
                logger.log_step(
                    f"SSH anomaly dataset: {len(df):,} rows × {len(df.columns)} columns ({file_size/1024:.1f} KB, {load_time:.2f}s)",
                    level="data"
                )
            
            return df
            
        except Exception as e:
            logger.log_error("Failed to load SSH anomaly dataset", exception=e)
            logging.error(f"Failed to load SSH anomaly dataset: {e}")
        
        return pd.DataFrame()
    
    def load_network_intrusion_data(self) -> pd.DataFrame:
        """Load network intrusion detection datasets (CICIDS2017) with detailed progress"""
        logger = self._get_logger()
        datasets = []
        
        # Get list of CSV files
        csv_files = list(self.datasets_dir.glob("*.pcap_ISCX.csv"))
        
        if not csv_files:
            if self.verbosity >= VerbosityLevel.DEBUG:
                logger.log_step("No CICIDS2017 CSV files found", level="debug")
            return pd.DataFrame()
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Loading {len(csv_files)} network intrusion dataset files...", level="info")
        
        total_rows = 0
        load_start = time.time()
        
        for file_idx, csv_file in enumerate(csv_files):
            file_start = time.time()
            
            try:
                file_size = csv_file.stat().st_size
                
                # Try different encodings to handle encoding issues
                df = None
                used_encoding = None
                
                for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                    try:
                        df = pd.read_csv(csv_file, encoding=encoding, low_memory=False)
                        used_encoding = encoding
                        break
                    except UnicodeDecodeError:
                        continue
                
                if df is None:
                    logger.log_error(f"Could not decode {csv_file.name} with any encoding")
                    logging.error(f"Could not decode {csv_file} with any encoding")
                    continue
                
                # Clean column names (remove leading/trailing spaces)
                df.columns = df.columns.str.strip()
                
                # Standardize the label column name
                if 'Label' not in df.columns and ' Label' in df.columns:
                    df = df.rename(columns={' Label': 'Label'})
                
                df['source_file'] = csv_file.name
                datasets.append(df)
                
                file_time = time.time() - file_start
                total_rows += len(df)
                
                # Log file loading
                if self.verbosity >= VerbosityLevel.VERBOSE:
                    logger.log_file_loaded(
                        csv_file.name,
                        len(df),
                        size_bytes=file_size,
                        cumulative=total_rows
                    )
                    
                    # Show label distribution for this file
                    if self.verbosity >= VerbosityLevel.DEBUG and 'Label' in df.columns:
                        unique_labels = df['Label'].nunique()
                        logger.log_step(
                            f"  Unique labels: {unique_labels}, Encoding: {used_encoding}",
                            level="debug",
                            indent=2
                        )
                
                logging.info(f"Loaded {csv_file.name}: {len(df)} rows")
                
            except Exception as e:
                logger.log_error(f"Failed to load {csv_file.name}", exception=e)
                logging.error(f"Failed to load {csv_file}: {e}")
        
        if datasets:
            combine_start = time.time()
            combined_df = pd.concat(datasets, ignore_index=True)
            combine_time = time.time() - combine_start
            total_time = time.time() - load_start
            
            if self.verbosity >= VerbosityLevel.NORMAL:
                logger.log_step(
                    f"Combined network intrusion data: {len(combined_df):,} rows "
                    f"from {len(datasets)} files in {total_time:.2f}s",
                    level="success"
                )
                
            if self.verbosity >= VerbosityLevel.VERBOSE:
                logger.log_data_stats(combined_df, "Combined Network Data")
                
                # Show label distribution
                if 'Label' in combined_df.columns:
                    labels = combined_df['Label'].value_counts()
                    logger.log_step(f"Attack types: {len(labels)} categories", level="data")
                    
                    if self.verbosity >= VerbosityLevel.DEBUG:
                        for label, count in labels.head(10).items():
                            pct = (count / len(combined_df)) * 100
                            logger.log_step(f"  {label}: {count:,} ({pct:.1f}%)", level="debug", indent=2)
            
            logging.info(f"Combined network intrusion data: {len(combined_df)} total rows")
            return combined_df
        
        return pd.DataFrame()
    
    def load_brute_force_data(self) -> List[Dict[str, Any]]:
        """Load brute force attack data with detailed logging"""
        logger = self._get_logger()
        
        try:
            json_file = self.datasets_dir / "brute_force_data.json"
            
            if not json_file.exists():
                if self.verbosity >= VerbosityLevel.DEBUG:
                    logger.log_step(f"Brute force data file not found", level="debug")
                return []
            
            file_size = json_file.stat().st_size
            load_start = time.time()
            
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            load_time = time.time() - load_start
            
            if self.verbosity >= VerbosityLevel.VERBOSE:
                logger.log_step(
                    f"Brute force data: {len(data):,} entries ({file_size/1024:.1f} KB, {load_time:.2f}s)",
                    level="data"
                )
            
            logging.info(f"Loaded brute force data: {len(data)} entries")
            return data
            
        except Exception as e:
            logger.log_error("Failed to load brute force data", exception=e)
            logging.error(f"Failed to load brute force data: {e}")
        
        return []
    
    def process_ssh_data(self) -> List[Dict[str, Any]]:
        """Process SSH-related data for training with detailed progress"""
        logger = self._get_logger()
        processed_data = []
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step("Processing SSH data...", level="info")
        
        process_start = time.time()
        
        # Process Cowrie logs
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step("Loading Cowrie honeypot logs...", level="debug")
        
        cowrie_logs = self.load_cowrie_logs()
        cowrie_commands = 0
        
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
                        'duration': 0,
                        'command_count': 1,
                        'failed_attempts': 0
                    }
                })
                cowrie_commands += 1
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Extracted {cowrie_commands:,} commands from Cowrie logs", level="data")
        
        # Process SSH anomaly dataset
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step("Loading SSH anomaly dataset...", level="debug")
        
        ssh_df = self.load_ssh_anomaly_dataset()
        ssh_anomaly_count = 0
        
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
                    ssh_anomaly_count += 1
            
            if self.verbosity >= VerbosityLevel.VERBOSE:
                logger.log_step(f"Extracted {ssh_anomaly_count:,} entries from SSH anomaly dataset", level="data")
        
        process_time = time.time() - process_start
        
        # Display label distribution
        if processed_data and self.verbosity >= VerbosityLevel.VERBOSE:
            labels = [item['label'] for item in processed_data]
            logger.log_label_distribution(labels, "SSH Data Labels")
        
        logger.log_step(
            f"Processed {len(processed_data):,} SSH data points in {process_time:.2f}s",
            level="success"
        )
        logging.info(f"Processed {len(processed_data)} SSH data points")
        
        return processed_data
    
    def process_mysql_data(self) -> List[Dict[str, Any]]:
        """Process MySQL-related data for training with detailed logging"""
        logger = self._get_logger()
        processed_data = []
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step("Processing MySQL data...", level="info")
        
        process_start = time.time()
        
        # Process network data for database attacks
        network_df = self.load_network_intrusion_data()
        
        if not network_df.empty:
            # Filter for potential database attacks (port 3306, SQL injection patterns)
            filter_start = time.time()
            
            db_attacks = network_df[
                (network_df['Destination Port'] == 3306) |
                network_df['Label'].str.contains('SQL', na=False)
            ]
            
            filter_time = time.time() - filter_start
            
            if self.verbosity >= VerbosityLevel.VERBOSE:
                logger.log_step(
                    f"Filtered {len(db_attacks):,} database-related entries from {len(network_df):,} records ({filter_time:.2f}s)",
                    level="data"
                )
            
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
        
        process_time = time.time() - process_start
        
        # Display label distribution
        if processed_data and self.verbosity >= VerbosityLevel.VERBOSE:
            labels = [item['label'] for item in processed_data]
            logger.log_label_distribution(labels, "MySQL Data Labels")
        
        logger.log_step(
            f"Processed {len(processed_data):,} MySQL data points in {process_time:.2f}s",
            level="success"
        )
        logging.info(f"Processed {len(processed_data)} MySQL data points")
        
        return processed_data
    
    def process_ftp_data(self) -> List[Dict[str, Any]]:
        """Process FTP-related data for training with detailed logging"""
        logger = self._get_logger()
        processed_data = []
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step("Processing FTP data...", level="info")
        
        process_start = time.time()
        
        # Process network data for FTP attacks
        network_df = self.load_network_intrusion_data()
        
        if not network_df.empty:
            # Filter for FTP traffic (port 21)
            filter_start = time.time()
            
            ftp_traffic = network_df[
                (network_df['Destination Port'] == 21) |
                (network_df['Source Port'] == 21)
            ]
            
            filter_time = time.time() - filter_start
            
            if self.verbosity >= VerbosityLevel.VERBOSE:
                logger.log_step(
                    f"Filtered {len(ftp_traffic):,} FTP-related entries from {len(network_df):,} records ({filter_time:.2f}s)",
                    level="data"
                )
            
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
        
        process_time = time.time() - process_start
        
        # Display label distribution
        if processed_data and self.verbosity >= VerbosityLevel.VERBOSE:
            labels = [item['label'] for item in processed_data]
            logger.log_label_distribution(labels, "FTP Data Labels")
        
        logger.log_step(
            f"Processed {len(processed_data):,} FTP data points in {process_time:.2f}s",
            level="success"
        )
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
        logger = self._get_logger()
        
        if not self.processed_data:
            if self.verbosity >= VerbosityLevel.NORMAL:
                logger.log_step("Processing all service data...", level="info")
            
            process_start = time.time()
            
            self.processed_data = {
                'ssh': self.process_ssh_data(),
                'mysql': self.process_mysql_data(),
                'ftp': self.process_ftp_data(),
            }
            
            total_time = time.time() - process_start
            total_samples = sum(len(data) for data in self.processed_data.values())
            
            if self.verbosity >= VerbosityLevel.NORMAL:
                logger.log_step(
                    f"Total processed: {total_samples:,} samples across {len(self.processed_data)} services ({total_time:.2f}s)",
                    level="success"
                )
        
        if service:
            return {service: self.processed_data.get(service, [])}
        
        return self.processed_data
    
    def save_processed_data(self, output_dir: str = None):
        """Save processed data to files with logging"""
        logger = self._get_logger()
        output_dir = Path(output_dir) if output_dir else self.datasets_dir.parent / "data"
        output_dir.mkdir(exist_ok=True)
        
        if self.verbosity >= VerbosityLevel.NORMAL:
            logger.log_step(f"Saving processed data to {output_dir}...", level="info")
        
        data = self.get_processed_data()
        
        for service, service_data in data.items():
            if service_data:
                output_file = output_dir / f"{service}_processed.json"
                
                save_start = time.time()
                with open(output_file, 'w') as f:
                    json.dump(service_data, f, indent=2)
                save_time = time.time() - save_start
                
                file_size = output_file.stat().st_size
                
                if self.verbosity >= VerbosityLevel.VERBOSE:
                    logger.log_step(
                        f"Saved {service}: {len(service_data):,} records ({file_size/1024:.1f} KB, {save_time:.2f}s)",
                        level="success"
                    )
                
                logging.info(f"Saved {len(service_data)} {service} records to {output_file}")
    
    def get_training_data(self, service: str, test_size: float = 0.2) -> Tuple[List[Dict], List[Dict]]:
        """Split data into training and testing sets with logging"""
        logger = self._get_logger()
        data = self.get_processed_data(service)[service]
        
        if not data:
            if self.verbosity >= VerbosityLevel.DEBUG:
                logger.log_step(f"No data available for {service}", level="warning")
            return [], []
        
        # Shuffle data
        np.random.shuffle(data)
        
        # Split
        split_idx = int(len(data) * (1 - test_size))
        train_data = data[:split_idx]
        test_data = data[split_idx:]
        
        if self.verbosity >= VerbosityLevel.DEBUG:
            logger.log_step(
                f"Split {service} data: {len(train_data):,} train / {len(test_data):,} test ({test_size:.0%} test)",
                level="data"
            )
        
        return train_data, test_data
