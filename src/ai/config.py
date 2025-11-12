"""
ML Configuration Manager for NEXUS AI
Handles per-service ML configuration and model paths
"""

import os
import json
from pathlib import Path
from configparser import ConfigParser
from typing import Dict, Any, Optional
import logging

class MLConfig:
    """Configuration manager for ML models and settings"""
    
    def __init__(self, service_name: str = None, config_path: str = None):
        self.service_name = service_name
        self.base_dir = Path(__file__).parent.parent.parent
        self.models_dir = self.base_dir / "models"
        self.data_dir = self.base_dir / "data"
        
        # Ensure directories exist
        self.models_dir.mkdir(exist_ok=True)
        self.data_dir.mkdir(exist_ok=True)
        
        # Default configuration
        self.config = self._load_default_config()
        
        # Load service-specific configuration if provided
        if config_path:
            self._load_service_config(config_path)
        elif service_name:
            self._load_service_config_by_name(service_name)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default ML configuration"""
        return {
            'ml': {
                'enabled': True,
                'anomaly_threshold': 0.95,
                'max_inference_ms': 15,
                'fallback_on_error': True,
                'embedding_model': 'sentence-transformers/all-MiniLM-L6-v2',
                'batch_size': 32,
                'cache_embeddings': True,
                'use_gpu': False,
                'model_update_interval': 3600,  # 1 hour
                'min_training_samples': 100
            },
            'models': {
                'isolation_forest': {
                    'n_estimators': 100,
                    'contamination': 0.05,
                    'random_state': 42
                },
                'one_class_svm': {
                    'kernel': 'rbf',
                    'gamma': 'scale',
                    'nu': 0.05
                },
                'lof': {
                    'n_neighbors': 20,
                    'contamination': 0.05
                },
                'hdbscan': {
                    'min_cluster_size': 5,
                    'min_samples': 3,
                    'cluster_selection_epsilon': 0.5
                },
                'xgboost': {
                    'n_estimators': 100,
                    'max_depth': 6,
                    'learning_rate': 0.1,
                    'random_state': 42
                }
            },
            'features': {
                'tfidf': {
                    'max_features': 5000,
                    'ngram_range': [3, 5],
                    'analyzer': 'char',
                    'lowercase': True
                },
                'numerical': {
                    'normalize': True,
                    'handle_missing': 'median'
                }
            }
        }
    
    def _load_service_config_by_name(self, service_name: str):
        """Load configuration for a specific service"""
        config_file = self.base_dir / "configs" / f"{service_name}_config.ini"
        if config_file.exists():
            self._load_service_config(str(config_file))
    
    def _load_service_config(self, config_path: str):
        """Load service-specific ML configuration from INI file"""
        try:
            parser = ConfigParser()
            parser.read(config_path)
            
            if 'ml' in parser:
                ml_section = dict(parser['ml'])
                # Convert string values to appropriate types
                for key, value in ml_section.items():
                    if value.lower() in ('true', 'false'):
                        ml_section[key] = value.lower() == 'true'
                    elif value.replace('.', '').isdigit():
                        ml_section[key] = float(value) if '.' in value else int(value)
                
                self.config['ml'].update(ml_section)
                
        except Exception as e:
            logging.warning(f"Failed to load ML config from {config_path}: {e}")
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(section, {}).get(key, default)
    
    def get_model_path(self, model_type: str, service: str = None) -> Path:
        """Get path for model file with proper filename mapping"""
        service = service or self.service_name or "global"
        service_dir = self.models_dir / service
        service_dir.mkdir(exist_ok=True)
        
        # Map model types to actual filenames
        model_files = {
            'anomaly_detector': 'isolation_forest_anomaly.pkl',
            'cluster_model': 'hdbscan_clustering.pkl',
            'supervised_classifier': 'supervised_classifier.pkl',
            'one_class_svm': 'one_class_svm_anomaly.pkl'
        }
        
        filename = model_files.get(model_type, f"{model_type}.pkl")
        return service_dir / filename
    
    def get_vectorizer_path(self, service: str = None) -> Path:
        """Get path for vectorizer file"""
        service = service or self.service_name or "global"
        service_dir = self.models_dir / service
        service_dir.mkdir(exist_ok=True)
        return service_dir / "vectorizer.pkl"
    
    def get_embedding_cache_path(self, service: str = None) -> Path:
        """Get path for embedding cache"""
        service = service or self.service_name or "global"
        service_dir = self.models_dir / service
        service_dir.mkdir(exist_ok=True)
        return service_dir / "embeddings.cache"
    
    def get_faiss_index_path(self, service: str = None) -> Path:
        """Get path for FAISS index"""
        service = service or self.service_name or "global"
        service_dir = self.models_dir / service
        service_dir.mkdir(exist_ok=True)
        return service_dir / "faiss.index"
    
    def get_data_path(self, filename: str) -> Path:
        """Get path for data file"""
        return self.data_dir / filename
    
    def is_enabled(self) -> bool:
        """Check if ML is enabled"""
        return self.get('ml', 'enabled', True)
    
    def get_anomaly_threshold(self) -> float:
        """Get anomaly detection threshold"""
        return self.get('ml', 'anomaly_threshold', 0.95)
    
    def get_max_inference_time(self) -> int:
        """Get maximum inference time in milliseconds"""
        return self.get('ml', 'max_inference_ms', 15)
    
    def should_fallback_on_error(self) -> bool:
        """Check if should fallback on ML errors"""
        return self.get('ml', 'fallback_on_error', True)
    
    def get_embedding_model(self) -> str:
        """Get embedding model name"""
        return self.get('ml', 'embedding_model', 'sentence-transformers/all-MiniLM-L6-v2')
    
    def save_config(self, config_path: str = None):
        """Save current configuration to file"""
        if not config_path and self.service_name:
            config_path = self.base_dir / "configs" / f"{self.service_name}_config.ini"
        
        if config_path:
            parser = ConfigParser()
            
            # Load existing config if it exists
            if Path(config_path).exists():
                parser.read(config_path)
            
            # Update ML section
            if 'ml' not in parser:
                parser.add_section('ml')
            
            for key, value in self.config['ml'].items():
                parser.set('ml', key, str(value))
            
            # Write to file
            with open(config_path, 'w') as f:
                parser.write(f)
    
    
    
    def get_scaler_path(self, service: str) -> Path:
        """Get path to scaler file"""
        return self.models_dir / service / "scaler.pkl"
    
    def get_label_encoder_path(self, service: str) -> Path:
        """Get path to label encoder file"""
        return self.models_dir / service / "label_encoder.pkl"
    
    def get_embedding_cache_path(self) -> Path:
        """Get path to embeddings cache"""
        if self.service_name:
            return self.models_dir / self.service_name / "embeddings.cache"
        return self.models_dir / "embeddings.cache"
    
    def get_faiss_index_path(self) -> Path:
        """Get path to FAISS index"""
        if self.service_name:
            return self.models_dir / self.service_name / "faiss.index"
        return self.models_dir / "faiss.index"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return self.config.copy()
    
    def update(self, updates: Dict[str, Any]):
        """Update configuration with new values"""
        for section, values in updates.items():
            if section in self.config:
                self.config[section].update(values)
            else:
                self.config[section] = values
