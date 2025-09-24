"""
ML Detectors for NEXUS AI - Anomaly detection and threat classification
"""

import numpy as np
import joblib
import time
import logging
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
        self.feature_extractor = FeatureExtractor(service_type, self.config.to_dict())
        
        # Initialize models
        self.anomaly_detector = None
        self.cluster_model = None
        self.supervised_model = None
        
        # Model metadata
        self.model_version = "1.0.0"
        self.last_update = None
        self.is_trained = False
        
        # Load existing models if available
        self._load_models()
    
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
                
            self.is_trained = self.anomaly_detector is not None and self.feature_extractor.vectorizer is not None
            
        except Exception as e:
            logging.error(f"Failed to load models for {self.service_type}: {e}")
    
    def score(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Score a single data point for anomalies and threats"""
        start_time = time.time()
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(data)
            
            # Initialize result
            result = {
                'ml_anomaly_score': 0.0,
                'ml_labels': [],
                'ml_cluster': -1,
                'ml_reason': 'No ML model available',
                'ml_model_version': self.model_version,
                'ml_inference_time_ms': 0,
                'ml_confidence': 0.0
            }
            
            if not self.is_trained:
                result['ml_reason'] = 'Models not trained'
                return result
            
            # Prepare feature vector
            text_features = [features.get('text_features', '')]
            numerical_features = []
            
            for key, value in features.items():
                if key != 'text_features' and isinstance(value, (int, float, bool)):
                    numerical_features.append(float(value))
            
            # Vectorize and combine features
            if self.feature_extractor.vectorizer:
                text_vector = self.feature_extractor.vectorizer.transform(text_features).toarray()
            else:
                text_vector = np.array([]).reshape(1, 0)
            
            numerical_array = np.array([numerical_features])
            if self.feature_extractor.scaler and numerical_array.size > 0:
                numerical_array = self.feature_extractor.scaler.transform(numerical_array)
            
            # Combine features
            feature_vector = self.feature_extractor.combine_features(text_vector, numerical_array)
            
            # Anomaly detection
            if self.anomaly_detector:
                anomaly_score = self.anomaly_detector.decision_function(feature_vector)[0]
                is_anomaly = self.anomaly_detector.predict(feature_vector)[0] == -1
                
                # Normalize score to 0-1 range
                normalized_score = max(0, min(1, (anomaly_score + 1) / 2))
                
                result['ml_anomaly_score'] = float(normalized_score)
                result['ml_confidence'] = float(abs(anomaly_score))
                
                if is_anomaly:
                    result['ml_labels'].append('anomaly')
                    result['ml_reason'] = f'Anomaly detected (score: {normalized_score:.3f})'
                else:
                    result['ml_labels'].append('normal')
                    result['ml_reason'] = f'Normal behavior (score: {normalized_score:.3f})'
            
            # Clustering
            if self.cluster_model:
                try:
                    cluster_id = self.cluster_model.predict(feature_vector)[0]
                    result['ml_cluster'] = int(cluster_id)
                    if cluster_id >= 0:
                        result['ml_labels'].append(f'cluster_{cluster_id}')
                except:
                    # Handle HDBSCAN or other clustering methods
                    pass
            
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
