"""
ML Detectors for NEXUS AI - Anomaly detection and threat classification
"""

import numpy as np
import joblib
import time
import logging
import os
import re
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN, KMeans
try:
    import hdbscan
    HDBSCAN_AVAILABLE = True
except ImportError:
    HDBSCAN_AVAILABLE = False
    logging.warning("HDBSCAN not available. Install with: pip install hdbscan")

from .config import MLConfig
from .features import FeatureExtractor

class MLDetector:
    """Main ML detector class for threat identification"""
    
    def __init__(self, service_type: str, config: MLConfig = None):
        self.service_type = service_type
        self.config = config or MLConfig(service_type)
        
        # Check if ML is globally disabled
        self.ml_disabled = os.getenv('NEXUS_DISABLE_ML', '').lower() in ('true', '1', 'yes')
        if self.ml_disabled:
            logging.info(f"ML disabled via environment variable for {service_type}")
        
        # Initialize components
        self.feature_extractor = None
        self.anomaly_detector = None
        self.cluster_model = None
        self.supervised_model = None
        
        # Model metadata
        self.model_version = "1.0.0"
        self.last_update = None
        self.is_trained = False
        
        if not self.ml_disabled:
            try:
                self.feature_extractor = FeatureExtractor(service_type, self.config.to_dict())
                # Load existing models if available
                self._load_models()
            except Exception as e:
                logging.error(f"Failed to initialize ML components for {service_type}: {e}")
                self.ml_disabled = True
    
    def _load_models(self):
        """Load pre-trained models if available"""
        try:
            anomaly_path = self.config.get_model_path('anomaly_detector', self.service_type)
            if anomaly_path.exists():
                self.anomaly_detector = joblib.load(anomaly_path)
                logging.info(f"Loaded anomaly detector for {self.service_type}")
            
            cluster_path = self.config.get_model_path('cluster_model', self.service_type)
            if cluster_path.exists():
                self.cluster_model = joblib.load(cluster_path)
                logging.info(f"Loaded cluster model for {self.service_type}")
            
            vectorizer_path = self.config.get_vectorizer_path(self.service_type)
            if vectorizer_path.exists():
                self.feature_extractor.vectorizer = joblib.load(vectorizer_path)
                logging.info(f"Loaded vectorizer for {self.service_type}")
            
            scaler_path = self.config.get_scaler_path(self.service_type)
            if scaler_path.exists():
                self.feature_extractor.scaler = joblib.load(scaler_path)
                logging.info(f"Loaded scaler for {self.service_type}")
                
            self.is_trained = (self.anomaly_detector is not None and 
                              self.feature_extractor is not None)
            
        except Exception as e:
            logging.error(f"Failed to load models for {self.service_type}: {e}")
    
    def _is_vectorizer_fitted(self) -> bool:
        """Check if the TF-IDF vectorizer is properly fitted"""
        try:
            if self.feature_extractor is None or self.feature_extractor.vectorizer is None:
                return False
            
            vectorizer = self.feature_extractor.vectorizer
            
            # Check for vocabulary_ attribute (sklearn fitted vectorizers have this)
            if hasattr(vectorizer, 'vocabulary_') and vectorizer.vocabulary_ is not None:
                return len(vectorizer.vocabulary_) > 0
            
            # Check for idf_ attribute (TF-IDF specific fitted indicator)
            if hasattr(vectorizer, 'idf_') and vectorizer.idf_ is not None:
                return len(vectorizer.idf_) > 0
                
            # Check if vocabulary attribute is set and not None
            if hasattr(vectorizer, 'vocabulary') and vectorizer.vocabulary is not None:
                return len(vectorizer.vocabulary) > 0
                
            return False
        except:
            return False
    
    def _get_expected_feature_count(self) -> Optional[int]:
        """Get the expected number of features for the trained model"""
        try:
            if self.anomaly_detector and hasattr(self.anomaly_detector, 'n_features_in_'):
                return self.anomaly_detector.n_features_in_
            return None
        except:
            return None
    
    def _create_risk_based_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Create risk-based feature vector for any service"""
        command_text = data.get('command', '')
        
        # Calculate multiple risk indicators
        risk_score = 0.0
        
        # 1. Command length (normalized)
        length_score = min(len(command_text) / 100.0, 1.0)
        
        # 2. Service-specific malicious keywords
        malicious_keywords = self._get_service_keywords()
        keyword_matches = sum(1 for keyword in malicious_keywords if keyword.lower() in command_text.lower())
        keyword_score = min(keyword_matches / 5.0, 1.0)
        
        # 3. Special characters and patterns
        special_chars = ['&', '|', ';', '>', '<', '`', '$', '(', ')', '"', "'", '\\', '/', '..']
        special_score = min(sum(1 for char in special_chars if char in command_text) / 10.0, 1.0)
        
        # 4. URL/IP patterns
        url_patterns = ['http://', 'https://', 'ftp://', '://']
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        url_score = 0.5 if any(pattern in command_text for pattern in url_patterns) else 0.0
        ip_score = 0.3 if re.search(ip_pattern, command_text) else 0.0
        
        # 5. Attack type context
        attack_types = data.get('attack_types', [])
        attack_score = min(len(attack_types) / 3.0, 1.0) if attack_types else 0.0
        
        # 6. Severity context
        severity_map = {'low': 0.1, 'medium': 0.4, 'high': 0.7, 'critical': 1.0}
        severity_score = severity_map.get(data.get('severity', 'low'), 0.1)
        
        # Combine all risk factors
        risk_score = (
            length_score * 0.1 +
            keyword_score * 0.3 +
            special_score * 0.15 +
            url_score * 0.2 +
            ip_score * 0.1 +
            attack_score * 0.1 +
            severity_score * 0.05
        )
        
        # Create feature vector - single feature for compatibility
        feature_vector = np.array([[risk_score]])
        logging.debug(f"Risk-based feature: {risk_score:.3f} for {self.service_type}")
        return feature_vector
    
    def _get_service_keywords(self) -> List[str]:
        """Get service-specific malicious keywords"""
        base_keywords = ['exploit', 'payload', 'malware', 'backdoor', 'shell']
        
        service_keywords = {
            'ssh': ['wget', 'curl', 'chmod +x', 'sudo', 'su -', 'passwd', 'shadow', 'nc -l', 'netcat', 'nmap'],
            'http': ['script', 'alert', 'eval', 'document.cookie', '../', 'union select', 'drop table', 'xss'],
            'ftp': ['RETR', 'STOR', '../', '..\\', 'passwd', 'shadow', 'config'],
            'mysql': ['union', 'select', 'drop', 'delete', 'insert', 'update', 'information_schema', '--', '#'],
            'smb': ['SMB_COM', 'TRANS2', 'NT_TRANSACT', 'exploit', 'buffer', 'overflow']
        }
        
        return base_keywords + service_keywords.get(self.service_type, [])
    
    def score(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Score a single data point for anomalies and threats"""
        start_time = time.time()
        
        try:
            # Validate input data type
            if not isinstance(data, dict):
                logging.error(f"ML detector received non-dict data: {type(data)} - {str(data)[:100]}")
                return {
                    'ml_anomaly_score': 0.0,
                    'ml_labels': ['input_error'],
                    'ml_cluster': -1,
                    'ml_reason': f'Invalid input type: {type(data)}',
                    'ml_model_version': self.model_version,
                    'ml_inference_time_ms': round((time.time() - start_time) * 1000, 2),
                    'ml_confidence': 0.0
                }
            
            # Initialize result with safe defaults
            result = {
                'ml_anomaly_score': 0.0,
                'ml_labels': [],
                'ml_cluster': -1,
                'ml_reason': 'ML analysis disabled',
                'ml_model_version': self.model_version,
                'ml_inference_time_ms': 0,
                'ml_confidence': 0.0
            }
            
            # Check if ML is disabled
            if self.ml_disabled:
                result['ml_reason'] = 'ML disabled via configuration'
                result['ml_inference_time_ms'] = round((time.time() - start_time) * 1000, 2)
                return result
            
            # Check if ML is properly initialized
            if not self.is_trained:
                result['ml_reason'] = 'ML models not available or not trained'
                result['ml_inference_time_ms'] = round((time.time() - start_time) * 1000, 2)
                return result
            
            # Check if we have at least anomaly detection capability
            if self.anomaly_detector is None:
                result['ml_reason'] = 'No anomaly detector available'
                result['ml_inference_time_ms'] = round((time.time() - start_time) * 1000, 2)
                return result
            
            # Extract features safely
            features = self.feature_extractor.extract_features(data)
            
            # Prepare feature vector with error handling
            text_features = [features.get('text_features', '')]
            numerical_features = []
            
            for key, value in features.items():
                if key != 'text_features' and isinstance(value, (int, float, bool)):
                    numerical_features.append(float(value))
            
            # Vectorize text features with safety checks
            text_vector = None
            if self.feature_extractor.vectorizer and self._is_vectorizer_fitted():
                try:
                    text_vector = self.feature_extractor.vectorizer.transform(text_features).toarray()
                except Exception as e:
                    logging.warning(f"Text vectorization failed: {e}")
                    text_vector = np.array([]).reshape(1, 0)
            else:
                text_vector = np.array([]).reshape(1, 0)
            
            # Process numerical features
            numerical_array = np.array([numerical_features]) if numerical_features else np.array([]).reshape(1, 0)
            
            # Skip scaling if scaler is not fitted
            scaler_fitted = False
            if self.feature_extractor.scaler and numerical_array.size > 0:
                try:
                    # Check if scaler is fitted by looking for scale_ attribute
                    if hasattr(self.feature_extractor.scaler, 'scale_') and self.feature_extractor.scaler.scale_ is not None:
                        numerical_array = self.feature_extractor.scaler.transform(numerical_array)
                        scaler_fitted = True
                    else:
                        logging.debug("Scaler not fitted, using raw numerical features")
                except Exception as e:
                    logging.warning(f"Numerical scaling failed: {e}")
            
            # Combine features safely
            feature_vector = self.feature_extractor.combine_features(text_vector, numerical_array)
            
            # Ensure we have a feature vector that matches the model's expectations
            # The IsolationForest model expects 1 feature, so we'll use command length as a simple feature
            command_text = data.get('command', '')
            
            # Create service-aware feature vectors
            command_text = data.get('command', '')
            
            # Check if we should use original features or fall back to risk-based
            expected_features = self._get_expected_feature_count()
            used_risk_based = True
            
            if feature_vector is not None and feature_vector.size > 0 and expected_features:
                if feature_vector.shape[1] == expected_features:
                    # Feature vector matches expected dimensions - use it
                    logging.debug(f"Using original feature vector: {feature_vector.shape}")
                    used_risk_based = False
                else:
                    # Dimension mismatch - log and fall back
                    logging.debug(f"Feature dimension mismatch: got {feature_vector.shape[1]}, expected {expected_features}")
            
            if used_risk_based:
                # Use risk-based features for compatibility
                feature_vector = self._create_risk_based_features(data)
                logging.debug(f"Using risk-based features for {self.service_type}")
            
            if feature_vector.size == 0:
                result['ml_reason'] = 'Invalid feature vector'
                result['ml_inference_time_ms'] = round((time.time() - start_time) * 1000, 2)
                return result
            
            # Anomaly detection with error handling
            if self.anomaly_detector and hasattr(self.anomaly_detector, 'decision_function'):
                try:
                    anomaly_score = self.anomaly_detector.decision_function(feature_vector)[0]
                    is_anomaly = self.anomaly_detector.predict(feature_vector)[0] == -1
                    
                    # Normalize score to 0-1 range
                    normalized_score = max(0, min(1, (anomaly_score + 1) / 2))
                    
                    # Calculate risk score separately for context
                    risk_features = self._create_risk_based_features(data)
                    risk_score = risk_features[0][0] if risk_features.size > 0 else 0.0
                    
                    # If we used risk-based features, the feature vector already contains the risk score
                    if used_risk_based:
                        risk_score = feature_vector[0][0]
                    
                    # Combine ML anomaly score with risk-based scoring
                    combined_score = (normalized_score * 0.7) + (risk_score * 0.3)
                    
                    result['ml_anomaly_score'] = float(combined_score)
                    result['ml_confidence'] = float(abs(anomaly_score))
                    result['ml_risk_score'] = float(risk_score)
                    
                    # More sensitive thresholds for malicious detection
                    if combined_score > 0.7 or risk_score > 0.6:
                        result['ml_labels'].append('anomaly')
                        result['ml_labels'].append('high_risk')
                        result['ml_reason'] = f'High-risk anomaly detected (combined: {combined_score:.3f}, risk: {risk_score:.3f})'
                    elif combined_score > 0.5 or risk_score > 0.3:
                        result['ml_labels'].append('anomaly')
                        result['ml_labels'].append('medium_risk')
                        result['ml_reason'] = f'Medium-risk anomaly detected (combined: {combined_score:.3f}, risk: {risk_score:.3f})'
                    elif risk_score > 0.1:
                        result['ml_labels'].append('suspicious')
                        result['ml_reason'] = f'Suspicious activity (combined: {combined_score:.3f}, risk: {risk_score:.3f})'
                    else:
                        result['ml_labels'].append('normal')
                        result['ml_reason'] = f'Normal behavior (combined: {combined_score:.3f}, risk: {risk_score:.3f})'
                except Exception as e:
                    logging.warning(f"Anomaly detection failed: {e}")
                    result['ml_reason'] = 'Anomaly detection unavailable'
            
            # Clustering with error handling
            if self.cluster_model and hasattr(self.cluster_model, 'predict'):
                try:
                    cluster_id = self.cluster_model.predict(feature_vector)[0]
                    result['ml_cluster'] = int(cluster_id)
                    if cluster_id >= 0:
                        result['ml_labels'].append(f'cluster_{cluster_id}')
                except Exception as e:
                    logging.warning(f"Clustering failed: {e}")
            
            # Calculate inference time
            inference_time = (time.time() - start_time) * 1000
            result['ml_inference_time_ms'] = round(inference_time, 2)
            
            # Check if inference time exceeds limit
            max_time = self.config.get_max_inference_time()
            if inference_time > max_time:
                logging.warning(f"ML inference took {inference_time:.2f}ms, exceeding limit of {max_time}ms")
            
            return result
            
        except Exception as e:
            logging.error(f"ML scoring failed for {self.service_type}: {e}")
            
            if self.config.should_fallback_on_error():
                return {
                    'ml_anomaly_score': 0.0,
                    'ml_labels': ['error'],
                    'ml_cluster': -1,
                    'ml_reason': f'ML error: {str(e)}',
                    'ml_model_version': self.model_version,
                    'ml_inference_time_ms': (time.time() - start_time) * 1000,
                    'ml_confidence': 0.0
                }
            else:
                raise
    
    def batch_score(self, data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score multiple data points efficiently"""
        return [self.score(data) for data in data_list]
    
    def calculate_risk_level(self, ml_score: float, attack_types: List[str] = None, severity: str = 'low') -> Dict[str, Any]:
        """Calculate comprehensive risk level from ML score and context"""
        attack_types = attack_types or []
        
        # Risk level thresholds
        risk_levels = {
            'critical': {'min_score': 0.8, 'color': '#dc3545', 'priority': 4},
            'high': {'min_score': 0.6, 'color': '#fd7e14', 'priority': 3},
            'medium': {'min_score': 0.4, 'color': '#ffc107', 'priority': 2},
            'low': {'min_score': 0.0, 'color': '#28a745', 'priority': 1}
        }
        
        # Determine base risk level from ML score
        risk_level = 'low'
        for level, config in sorted(risk_levels.items(), key=lambda x: x[1]['priority'], reverse=True):
            if ml_score >= config['min_score']:
                risk_level = level
                break
        
        # Adjust based on severity
        severity_boost = {'critical': 0.3, 'high': 0.2, 'medium': 0.1, 'low': 0.0}
        adjusted_score = min(1.0, ml_score + severity_boost.get(severity, 0.0))
        
        # Recalculate with adjusted score
        for level, config in sorted(risk_levels.items(), key=lambda x: x[1]['priority'], reverse=True):
            if adjusted_score >= config['min_score']:
                risk_level = level
                break
        
        # Calculate threat score (0-100)
        threat_score = int(adjusted_score * 100)
        
        return {
            'risk_level': risk_level,
            'risk_score': round(adjusted_score, 3),
            'threat_score': threat_score,
            'color': risk_levels[risk_level]['color'],
            'priority': risk_levels[risk_level]['priority'],
            'ml_contribution': round(ml_score, 3),
            'severity_contribution': round(severity_boost.get(severity, 0.0), 3)
        }
    
    def detect_attack_vectors(self, data: Dict[str, Any], ml_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect specific attack vectors based on service type and ML analysis"""
        attack_vectors = []
        command = data.get('command', '')
        ml_score = ml_results.get('ml_anomaly_score', 0.0)
        
        # Service-specific attack vector detection
        if self.service_type == 'ssh':
            attack_vectors.extend(self._detect_ssh_attack_vectors(command, ml_score))
        elif self.service_type == 'http':
            attack_vectors.extend(self._detect_http_attack_vectors(command, ml_score))
        elif self.service_type == 'ftp':
            attack_vectors.extend(self._detect_ftp_attack_vectors(command, ml_score))
        elif self.service_type == 'mysql':
            attack_vectors.extend(self._detect_mysql_attack_vectors(command, ml_score))
        elif self.service_type == 'smb':
            attack_vectors.extend(self._detect_smb_attack_vectors(command, ml_score))
        
        return attack_vectors
    
    def _detect_ssh_attack_vectors(self, command: str, ml_score: float) -> List[Dict[str, Any]]:
        """Detect SSH-specific attack vectors"""
        vectors = []
        cmd_lower = command.lower()
        
        # Brute force / credential stuffing
        if any(pattern in cmd_lower for pattern in ['passwd', 'shadow', 'ssh-keygen']):
            vectors.append({
                'type': 'credential_access',
                'technique': 'Credential Dumping',
                'mitre_id': 'T1003',
                'confidence': min(0.9, ml_score + 0.2),
                'description': 'Attempt to access credential files'
            })
        
        # Malware deployment
        if any(pattern in cmd_lower for pattern in ['wget', 'curl']) and any(ext in cmd_lower for ext in ['.sh', '.py', '.elf']):
            vectors.append({
                'type': 'malware_deployment',
                'technique': 'Ingress Tool Transfer',
                'mitre_id': 'T1105',
                'confidence': min(0.95, ml_score + 0.3),
                'description': 'Downloading potentially malicious files'
            })
        
        # Privilege escalation
        if any(pattern in cmd_lower for pattern in ['sudo', 'su -', 'chmod +s']):
            vectors.append({
                'type': 'privilege_escalation',
                'technique': 'Sudo and Sudo Caching',
                'mitre_id': 'T1548.003',
                'confidence': min(0.85, ml_score + 0.25),
                'description': 'Privilege escalation attempt detected'
            })
        
        # Persistence
        if any(pattern in cmd_lower for pattern in ['crontab', 'systemctl', '.bashrc', '.profile']):
            vectors.append({
                'type': 'persistence',
                'technique': 'Scheduled Task/Job',
                'mitre_id': 'T1053',
                'confidence': min(0.8, ml_score + 0.2),
                'description': 'Persistence mechanism creation'
            })
        
        # Reconnaissance
        if any(pattern in cmd_lower for pattern in ['whoami', 'uname', 'netstat', 'ps aux', 'ifconfig']):
            vectors.append({
                'type': 'reconnaissance',
                'technique': 'System Information Discovery',
                'mitre_id': 'T1082',
                'confidence': min(0.7, ml_score + 0.1),
                'description': 'System reconnaissance activity'
            })
        
        return vectors
    
    def _detect_http_attack_vectors(self, command: str, ml_score: float) -> List[Dict[str, Any]]:
        """Detect HTTP-specific attack vectors"""
        vectors = []
        cmd_lower = command.lower()
        
        # XSS
        if any(pattern in cmd_lower for pattern in ['<script', 'alert(', 'onerror=', 'javascript:']):
            vectors.append({
                'type': 'xss',
                'technique': 'Cross-Site Scripting',
                'mitre_id': 'T1059.007',
                'confidence': min(0.9, ml_score + 0.3),
                'description': 'Cross-site scripting attempt'
            })
        
        # SQL Injection
        if any(pattern in cmd_lower for pattern in ['union select', "' or '1'='1", 'drop table', '--', 'information_schema']):
            vectors.append({
                'type': 'sql_injection',
                'technique': 'SQL Injection',
                'mitre_id': 'T1190',
                'confidence': min(0.95, ml_score + 0.35),
                'description': 'SQL injection attack detected'
            })
        
        # Path traversal
        if '../' in command or '..\\' in command:
            vectors.append({
                'type': 'path_traversal',
                'technique': 'Path Traversal',
                'mitre_id': 'T1083',
                'confidence': min(0.85, ml_score + 0.25),
                'description': 'Directory traversal attempt'
            })
        
        # Command injection
        if any(pattern in command for pattern in ['|', ';', '&&', '`', '$(' ]):
            vectors.append({
                'type': 'command_injection',
                'technique': 'Command Injection',
                'mitre_id': 'T1059',
                'confidence': min(0.8, ml_score + 0.2),
                'description': 'Command injection attempt'
            })
        
        return vectors
    
    def _detect_ftp_attack_vectors(self, command: str, ml_score: float) -> List[Dict[str, Any]]:
        """Detect FTP-specific attack vectors"""
        vectors = []
        cmd_upper = command.upper()
        
        # Path traversal
        if '../' in command or '..\\' in command:
            vectors.append({
                'type': 'path_traversal',
                'technique': 'File and Directory Discovery',
                'mitre_id': 'T1083',
                'confidence': min(0.9, ml_score + 0.3),
                'description': 'FTP path traversal attempt'
            })
        
        # Sensitive file access
        if any(pattern in command.lower() for pattern in ['passwd', 'shadow', '.ssh', 'config', '.env']):
            vectors.append({
                'type': 'data_exfiltration',
                'technique': 'Data from Local System',
                'mitre_id': 'T1005',
                'confidence': min(0.85, ml_score + 0.25),
                'description': 'Attempt to access sensitive files'
            })
        
        # Anonymous login abuse
        if 'USER anonymous' in cmd_upper or 'USER ftp' in cmd_upper:
            vectors.append({
                'type': 'anonymous_access',
                'technique': 'Valid Accounts',
                'mitre_id': 'T1078',
                'confidence': min(0.6, ml_score + 0.1),
                'description': 'Anonymous FTP access attempt'
            })
        
        return vectors
    
    def _detect_mysql_attack_vectors(self, command: str, ml_score: float) -> List[Dict[str, Any]]:
        """Detect MySQL-specific attack vectors"""
        vectors = []
        cmd_lower = command.lower()
        
        # SQL Injection
        if any(pattern in cmd_lower for pattern in ['union select', "' or '", 'drop table', 'drop database']):
            vectors.append({
                'type': 'sql_injection',
                'technique': 'SQL Injection',
                'mitre_id': 'T1190',
                'confidence': min(0.95, ml_score + 0.4),
                'description': 'SQL injection attack'
            })
        
        # Information disclosure
        if 'information_schema' in cmd_lower or 'mysql.user' in cmd_lower:
            vectors.append({
                'type': 'information_disclosure',
                'technique': 'Data from Information Repositories',
                'mitre_id': 'T1213',
                'confidence': min(0.85, ml_score + 0.3),
                'description': 'Database schema enumeration'
            })
        
        # Privilege escalation
        if any(pattern in cmd_lower for pattern in ['grant all', 'create user', 'alter user']):
            vectors.append({
                'type': 'privilege_escalation',
                'technique': 'Valid Accounts',
                'mitre_id': 'T1078',
                'confidence': min(0.9, ml_score + 0.35),
                'description': 'Database privilege escalation'
            })
        
        # Data exfiltration
        if any(pattern in cmd_lower for pattern in ['into outfile', 'load_file', 'select * from']):
            vectors.append({
                'type': 'data_exfiltration',
                'technique': 'Automated Exfiltration',
                'mitre_id': 'T1020',
                'confidence': min(0.8, ml_score + 0.25),
                'description': 'Potential data exfiltration'
            })
        
        return vectors
    
    def _detect_smb_attack_vectors(self, command: str, ml_score: float) -> List[Dict[str, Any]]:
        """Detect SMB-specific attack vectors"""
        vectors = []
        cmd_upper = command.upper()
        
        # EternalBlue / SMB exploits
        if any(pattern in cmd_upper for pattern in ['SMB_COM_TRANSACTION', 'NT_TRANSACT', 'TRANS2']):
            vectors.append({
                'type': 'exploit',
                'technique': 'Exploitation for Client Execution',
                'mitre_id': 'T1203',
                'confidence': min(0.95, ml_score + 0.4),
                'description': 'SMB exploit attempt (potential EternalBlue)'
            })
        
        # Share enumeration
        if 'TREE_CONNECT' in cmd_upper or 'NET_SHARE_ENUM' in cmd_upper:
            vectors.append({
                'type': 'reconnaissance',
                'technique': 'Network Share Discovery',
                'mitre_id': 'T1135',
                'confidence': min(0.75, ml_score + 0.2),
                'description': 'SMB share enumeration'
            })
        
        # Path traversal
        if '../' in command or '..\\' in command:
            vectors.append({
                'type': 'path_traversal',
                'technique': 'File and Directory Discovery',
                'mitre_id': 'T1083',
                'confidence': min(0.85, ml_score + 0.3),
                'description': 'SMB path traversal attempt'
            })
        
        return vectors
    
    def analyze_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform session-level ML analysis by aggregating command-level results"""
        commands = session_data.get('commands', [])
        
        if not commands:
            return {
                'session_ml_score': 0.0,
                'session_risk_level': 'low',
                'session_threat_score': 0,
                'total_commands': 0,
                'malicious_commands': 0,
                'attack_vectors': [],
                'ml_insights': ['No commands to analyze']
            }
        
        # Aggregate ML scores
        ml_scores = []
        attack_vectors_all = []
        malicious_count = 0
        
        for cmd in commands:
            attack_analysis = cmd.get('attack_analysis', {})
            ml_score = attack_analysis.get('ml_anomaly_score', 0.0)
            ml_scores.append(ml_score)
            
            # Count malicious commands (score > 0.5)
            if ml_score > 0.5:
                malicious_count += 1
            
            # Collect attack vectors
            if 'attack_vectors' in attack_analysis:
                attack_vectors_all.extend(attack_analysis['attack_vectors'])
        
        # Calculate session-level metrics
        avg_ml_score = np.mean(ml_scores) if ml_scores else 0.0
        max_ml_score = np.max(ml_scores) if ml_scores else 0.0
        
        # Session score is weighted average of mean and max
        session_ml_score = (avg_ml_score * 0.4) + (max_ml_score * 0.6)
        
        # Calculate risk level
        risk_info = self.calculate_risk_level(
            session_ml_score,
            attack_types=[],
            severity='high' if malicious_count > len(commands) * 0.5 else 'medium'
        )
        
        # Deduplicate attack vectors by type
        unique_vectors = {}
        for vector in attack_vectors_all:
            vec_type = vector.get('type', 'unknown')
            if vec_type not in unique_vectors or vector.get('confidence', 0) > unique_vectors[vec_type].get('confidence', 0):
                unique_vectors[vec_type] = vector
        
        # Generate insights
        insights = []
        if session_ml_score > 0.7:
            insights.append(f'High-risk session detected with {malicious_count}/{len(commands)} malicious commands')
        elif session_ml_score > 0.5:
            insights.append(f'Medium-risk session with {malicious_count}/{len(commands)} suspicious commands')
        else:
            insights.append(f'Low-risk session with {malicious_count}/{len(commands)} flagged commands')
        
        if unique_vectors:
            insights.append(f'Detected {len(unique_vectors)} unique attack vector types')
        
        return {
            'session_ml_score': round(session_ml_score, 3),
            'session_risk_level': risk_info['risk_level'],
            'session_threat_score': risk_info['threat_score'],
            'session_risk_color': risk_info['color'],
            'total_commands': len(commands),
            'malicious_commands': malicious_count,
            'avg_ml_score': round(avg_ml_score, 3),
            'max_ml_score': round(max_ml_score, 3),
            'attack_vectors': list(unique_vectors.values()),
            'ml_insights': insights,
            'ml_model_version': self.model_version
        }
    
    def save_models(self):
        """Save trained models to disk"""
        try:
            if self.anomaly_detector:
                anomaly_path = self.config.get_model_path('anomaly_detector', self.service_type)
                joblib.dump(self.anomaly_detector, anomaly_path)
            
            if self.cluster_model:
                cluster_path = self.config.get_model_path('cluster_model', self.service_type)
                joblib.dump(self.cluster_model, cluster_path)
            
            if self.feature_extractor.vectorizer:
                vectorizer_path = self.config.get_vectorizer_path(self.service_type)
                joblib.dump(self.feature_extractor.vectorizer, vectorizer_path)
            
            logging.info(f"Saved models for {self.service_type}")
            
        except Exception as e:
            logging.error(f"Failed to save models for {self.service_type}: {e}")

class AnomalyDetector:
    """Specialized anomaly detection using multiple algorithms"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.models = {}
        self.ensemble_weights = {}
    
    def train_isolation_forest(self, X: np.ndarray, **kwargs) -> IsolationForest:
        """Train Isolation Forest model"""
        params = self.config.get('models', {}).get('isolation_forest', {})
        params.update(kwargs)
        
        model = IsolationForest(**params)
        model.fit(X)
        
        self.models['isolation_forest'] = model
        self.ensemble_weights['isolation_forest'] = 0.4
        
        return model
    
    def train_one_class_svm(self, X: np.ndarray, **kwargs) -> OneClassSVM:
        """Train One-Class SVM model"""
        params = self.config.get('models', {}).get('one_class_svm', {})
        params.update(kwargs)
        
        model = OneClassSVM(**params)
        model.fit(X)
        
        self.models['one_class_svm'] = model
        self.ensemble_weights['one_class_svm'] = 0.3
        
        return model
    
    def train_lof(self, X: np.ndarray, **kwargs) -> LocalOutlierFactor:
        """Train Local Outlier Factor model"""
        params = self.config.get('models', {}).get('lof', {})
        params.update(kwargs)
        
        model = LocalOutlierFactor(novelty=True, **params)
        model.fit(X)
        
        self.models['lof'] = model
        self.ensemble_weights['lof'] = 0.3
        
        return model
    
    def predict_ensemble(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Ensemble prediction from multiple models"""
        if not self.models:
            raise ValueError("No models trained")
        
        predictions = []
        scores = []
        
        for name, model in self.models.items():
            try:
                pred = model.predict(X)
                score = model.decision_function(X) if hasattr(model, 'decision_function') else pred
                
                predictions.append(pred * self.ensemble_weights[name])
                scores.append(score * self.ensemble_weights[name])
                
            except Exception as e:
                logging.warning(f"Model {name} prediction failed: {e}")
        
        if not predictions:
            raise ValueError("All model predictions failed")
        
        # Combine predictions
        ensemble_pred = np.sum(predictions, axis=0)
        ensemble_score = np.sum(scores, axis=0)
        
        # Convert to binary predictions
        final_pred = np.where(ensemble_pred < 0, -1, 1)
        
        return final_pred, ensemble_score
