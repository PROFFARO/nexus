"""
Feature extraction for different service types in NEXUS AI
Handles text vectorization, numerical features, and service-specific patterns
"""

import re
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder
import logging
from datetime import datetime
import hashlib

class FeatureExtractor:
    """Base feature extractor for all services"""
    
    def __init__(self, service_type: str, config: Dict[str, Any] = None):
        self.service_type = service_type.lower()
        self.config = config or {}
        self.vectorizer = None
        self.scaler = None
        self.label_encoder = None
        self._setup_extractors()
    
    def _setup_extractors(self):
        """Setup service-specific extractors"""
        tfidf_config = self.config.get('features', {}).get('tfidf', {})
        self.vectorizer = TfidfVectorizer(
            max_features=tfidf_config.get('max_features', 5000),
            ngram_range=tuple(tfidf_config.get('ngram_range', [3, 5])),
            analyzer=tfidf_config.get('analyzer', 'char'),
            lowercase=tfidf_config.get('lowercase', True)
        )
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
    
    def is_vectorizer_fitted(self) -> bool:
        """Check if the TF-IDF vectorizer is fitted"""
        try:
            return (hasattr(self.vectorizer, 'vocabulary_') and 
                   self.vectorizer.vocabulary_ is not None and 
                   len(self.vectorizer.vocabulary_) > 0)
        except:
            return False
    
    def extract_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features based on service type"""
        if self.service_type == 'ssh':
            return self._extract_ssh_features(data)
        elif self.service_type == 'http':
            return self._extract_http_features(data)
        elif self.service_type == 'ftp':
            return self._extract_ftp_features(data)
        elif self.service_type == 'mysql':
            return self._extract_mysql_features(data)
        elif self.service_type == 'smb':
            return self._extract_smb_features(data)
        else:
            return self._extract_generic_features(data)
    
    def _extract_ssh_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SSH-specific features"""
        command = data.get('command', '')
        session_data = data.get('session_data', {})
        
        features = {
            'text_features': command,
            'command_length': len(command),
            'command_entropy': self._calculate_entropy(command),
            'has_special_chars': len(re.findall(r'[;&|`$(){}[\]<>]', command)) > 0,
            'privilege_keywords': len(re.findall(r'\b(sudo|su|root|admin)\b', command, re.I)),
            'file_operations': len(re.findall(r'\b(cat|ls|cd|mkdir|rm|cp|mv|chmod|chown)\b', command, re.I)),
            'network_operations': len(re.findall(r'\b(wget|curl|nc|netcat|ssh|scp|ftp)\b', command, re.I)),
            'system_info': len(re.findall(r'\b(whoami|id|uname|ps|top|netstat|ifconfig)\b', command, re.I)),
            'directory_depth': command.count('/'),
            'pipe_count': command.count('|'),
            'redirect_count': command.count('>') + command.count('<'),
            'session_duration': session_data.get('duration', 0),
            'commands_per_session': session_data.get('command_count', 1),
            'failed_attempts': session_data.get('failed_attempts', 0)
        }
        
        return features
    
    def _extract_http_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract HTTP-specific features"""
        # Validate input data type
        if not isinstance(data, dict):
            logging.warning(f"HTTP feature extractor received non-dict data: {type(data)}")
            return {
                'text_features': str(data) if data else '',
                'url_length': len(str(data)) if data else 0,
                'query_params': 0,
                'path_segments': 0,
                'suspicious_keywords': 0,
                'sql_injection_patterns': 0,
                'xss_patterns': 0,
                'path_traversal': 0,
                'user_agent_length': 0,
                'has_referer': False,
                'content_length': 0,
                'header_count': 0,
                'suspicious_extensions': 0
            }
        
        request = data.get('request', '')
        headers = data.get('headers', {})
        url = data.get('url', '')
        method = data.get('method', 'GET')
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        features = {
            'text_features': f"{method} {url} {str(headers)}",
            'method': method,
            'url_length': len(url),
            'path_segments': len(parsed_url.path.split('/')) - 1,
            'query_params_count': len(query_params),
            'has_query_params': len(query_params) > 0,
            'special_chars_ratio': len(re.findall(r'[<>"\';()&+]', url)) / max(len(url), 1),
            'sql_injection_patterns': len(re.findall(r'(union|select|insert|update|delete|drop|exec)', url, re.I)),
            'xss_patterns': len(re.findall(r'(<script|javascript:|onload=|onerror=)', url, re.I)),
            'path_traversal': len(re.findall(r'(\.\./|\.\.\\)', url)),
            'user_agent_length': len(headers.get('User-Agent', '')),
            'has_referer': 'Referer' in headers,
            'content_length': int(headers.get('Content-Length', 0)),
            'header_count': len(headers),
            'suspicious_extensions': len(re.findall(r'\.(php|asp|jsp|cgi|pl)$', parsed_url.path, re.I))
        }
        
        return features
    
    def _extract_ftp_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract FTP-specific features"""
        command = data.get('command', '')
        filename = data.get('filename', '')
        session_data = data.get('session_data', {})
        
        features = {
            'text_features': f"{command} {filename}",
            'command_type': command.split()[0].upper() if command else '',
            'filename_length': len(filename),
            'has_suspicious_extension': len(re.findall(r'\.(exe|bat|cmd|scr|pif|com)$', filename, re.I)) > 0,
            'has_hidden_file': filename.startswith('.'),
            'directory_traversal': len(re.findall(r'(\.\./|\.\.\\)', filename)),
            'bytes_transferred': session_data.get('bytes_transferred', 0),
            'transfer_rate': session_data.get('transfer_rate', 0),
            'passive_mode': session_data.get('passive_mode', False),
            'anonymous_login': session_data.get('anonymous_login', False),
            'failed_logins': session_data.get('failed_logins', 0),
            'file_operations_count': session_data.get('file_operations', 0),
            'upload_count': session_data.get('uploads', 0),
            'download_count': session_data.get('downloads', 0)
        }
        
        return features
    
    def _extract_mysql_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract MySQL-specific features"""
        query = data.get('query', '')
        session_data = data.get('session_data', {})
        
        # Parse query type
        query_type = 'UNKNOWN'
        if query:
            first_word = query.strip().split()[0].upper()
            if first_word in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'SHOW', 'DESCRIBE']:
                query_type = first_word
        
        features = {
            'text_features': query,
            'query_type': query_type,
            'query_length': len(query),
            'query_entropy': self._calculate_entropy(query),
            'union_count': len(re.findall(r'\bunion\b', query, re.I)),
            'or_count': len(re.findall(r'\bor\b', query, re.I)),
            'and_count': len(re.findall(r'\band\b', query, re.I)),
            'comment_patterns': len(re.findall(r'(--|#|/\*)', query)),
            'sql_injection_patterns': len(re.findall(r'(1=1|1=0|\'=\'|"="|sleep\(|benchmark\()', query, re.I)),
            'information_schema': 'information_schema' in query.lower(),
            'system_functions': len(re.findall(r'\b(user\(\)|version\(\)|database\(\))\b', query, re.I)),
            'subquery_count': query.count('(') - query.count(')'),
            'table_count': len(re.findall(r'\bfrom\s+\w+', query, re.I)),
            'where_clauses': len(re.findall(r'\bwhere\b', query, re.I)),
            'session_queries': session_data.get('query_count', 1),
            'failed_queries': session_data.get('failed_queries', 0)
        }
        
        return features
    
    def _extract_smb_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SMB-specific features"""
        command = data.get('command', '')
        path = data.get('path', '')
        session_data = data.get('session_data', {})
        
        features = {
            'text_features': f"{command} {path}",
            'command_type': command,
            'path_length': len(path),
            'path_depth': path.count('\\') + path.count('/'),
            'has_admin_share': path.startswith('\\\\') and ('admin$' in path.lower() or 'c$' in path.lower()),
            'directory_traversal': len(re.findall(r'(\.\./|\.\.\\)', path)),
            'executable_access': len(re.findall(r'\.(exe|bat|cmd|scr|dll)$', path, re.I)) > 0,
            'system_directories': len(re.findall(r'\\(windows|system32|syswow64)\\', path, re.I)),
            'read_operations': session_data.get('read_ops', 0),
            'write_operations': session_data.get('write_ops', 0),
            'delete_operations': session_data.get('delete_ops', 0),
            'bytes_read': session_data.get('bytes_read', 0),
            'bytes_written': session_data.get('bytes_written', 0),
            'failed_operations': session_data.get('failed_ops', 0)
        }
        
        return features
    
    def _extract_generic_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract generic features for unknown service types"""
        text_data = str(data.get('text', ''))
        
        features = {
            'text_features': text_data,
            'text_length': len(text_data),
            'text_entropy': self._calculate_entropy(text_data),
            'special_chars_count': len(re.findall(r'[^a-zA-Z0-9\s]', text_data)),
            'numeric_count': len(re.findall(r'\d', text_data)),
            'uppercase_ratio': sum(1 for c in text_data if c.isupper()) / max(len(text_data), 1),
            'whitespace_ratio': sum(1 for c in text_data if c.isspace()) / max(len(text_data), 1)
        }
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def vectorize_text(self, texts: List[str], fit: bool = False) -> np.ndarray:
        """Vectorize text features using TF-IDF"""
        # Handle empty or all-empty texts
        if not texts or all(not text.strip() for text in texts):
            return np.zeros((len(texts) if texts else 0, 1))
        
        try:
            if fit:
                result = self.vectorizer.fit_transform(texts).toarray()
            else:
                result = self.vectorizer.transform(texts).toarray()
            
            # Ensure result is 2D and has at least 1 column
            if result.ndim == 1:
                result = result.reshape(-1, 1)
            elif result.shape[1] == 0:
                result = np.zeros((result.shape[0], 1))
            
            return result
        except Exception as e:
            logging.warning(f"Text vectorization failed: {e}. Using fallback.")
            # Fallback: return zero matrix with proper shape
            return np.zeros((len(texts), 1))
    
    def scale_numerical(self, features: np.ndarray, fit: bool = False) -> np.ndarray:
        """Scale numerical features"""
        if features.size == 0:
            return features
        
        # Ensure features is 2D
        if features.ndim == 1:
            features = features.reshape(-1, 1)
        
        # Handle case where features might be a single float
        if not isinstance(features, np.ndarray):
            features = np.array(features)
            if features.ndim == 0:
                features = features.reshape(1, 1)
        
        try:
            if fit:
                result = self.scaler.fit_transform(features)
            else:
                result = self.scaler.transform(features)
            
            # Ensure result is 2D
            if result.ndim == 1:
                result = result.reshape(-1, 1)
            elif result.ndim == 0:
                result = result.reshape(1, 1)
                
            return result
        except Exception as e:
            logging.warning(f"Numerical scaling failed: {e}. Using original features.")
            # Fallback: return original features
            return features
    
    def extract_batch_features(self, data_list: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features from a batch of data"""
        if not data_list:
            return np.zeros((0, 1)), np.zeros((0, 0))
            
        text_features = []
        numerical_features = []
        
        for data in data_list:
            features = self.extract_features(data)
            text_features.append(str(features.get('text_features', '')))
            
            # Extract numerical features
            numerical = []
            for key, value in features.items():
                if key != 'text_features' and isinstance(value, (int, float, bool)):
                    # Ensure we have a valid numerical value
                    try:
                        num_val = float(value)
                        if not np.isnan(num_val) and not np.isinf(num_val):
                            numerical.append(num_val)
                        else:
                            numerical.append(0.0)
                    except (ValueError, TypeError):
                        numerical.append(0.0)
            
            # Ensure all rows have the same number of features
            if not numerical_features:
                # First row - establish the feature count
                numerical_features.append(numerical)
            else:
                # Ensure consistent feature count
                expected_len = len(numerical_features[0])
                if len(numerical) < expected_len:
                    numerical.extend([0.0] * (expected_len - len(numerical)))
                elif len(numerical) > expected_len:
                    numerical = numerical[:expected_len]
                numerical_features.append(numerical)
        
        # Vectorize text features
        text_vectors = self.vectorize_text(text_features, fit=True)
        
        # Scale numerical features
        if numerical_features and len(numerical_features[0]) > 0:
            numerical_array = np.array(numerical_features, dtype=np.float64)
            numerical_scaled = self.scale_numerical(numerical_array, fit=True)
        else:
            # Create empty array with correct shape
            numerical_scaled = np.zeros((len(data_list), 0))
        
        return text_vectors, numerical_scaled
    
    def combine_features(self, text_vectors: np.ndarray, numerical_features: np.ndarray) -> np.ndarray:
        """Combine text and numerical features"""
        # Handle edge cases first
        if not isinstance(text_vectors, np.ndarray):
            text_vectors = np.array(text_vectors)
        if not isinstance(numerical_features, np.ndarray):
            numerical_features = np.array(numerical_features)
            
        # Ensure both inputs are 2D arrays
        if text_vectors.ndim == 0:
            text_vectors = text_vectors.reshape(1, 1)
        elif text_vectors.ndim == 1:
            text_vectors = text_vectors.reshape(-1, 1)
            
        if numerical_features.ndim == 0:
            numerical_features = numerical_features.reshape(1, 1)
        elif numerical_features.ndim == 1:
            numerical_features = numerical_features.reshape(-1, 1)
        
        if text_vectors.size == 0 and numerical_features.size == 0:
            # Both empty - return minimal 2D array
            return np.zeros((1, 1))
        elif text_vectors.size == 0:
            # Only numerical features
            if numerical_features.shape[1] == 0:
                return np.zeros((numerical_features.shape[0], 1))
            return numerical_features
        elif numerical_features.size == 0 or numerical_features.shape[1] == 0:
            # Only text features
            if text_vectors.shape[1] == 0:
                return np.zeros((text_vectors.shape[0], 1))
            return text_vectors
        else:
            # Ensure both arrays have the same number of rows
            if text_vectors.shape[0] != numerical_features.shape[0]:
                min_rows = min(text_vectors.shape[0], numerical_features.shape[0])
                text_vectors = text_vectors[:min_rows]
                numerical_features = numerical_features[:min_rows]
                logging.warning(f"Row mismatch fixed: using {min_rows} rows")
            
            combined = np.hstack([text_vectors, numerical_features])
            
            # Ensure result is 2D and has at least 1 column
            if combined.ndim == 1:
                combined = combined.reshape(-1, 1)
            elif combined.shape[1] == 0:
                combined = np.zeros((combined.shape[0], 1))
                
            return combined
