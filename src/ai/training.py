"""
Model Training for NEXUS AI - Train and evaluate ML models for threat detection
"""

import numpy as np
import pandas as pd
import joblib
import logging
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb

try:
    import hdbscan
    HDBSCAN_AVAILABLE = True
except ImportError:
    HDBSCAN_AVAILABLE = False

from .config import MLConfig
from .features import FeatureExtractor
from .detectors import MLDetector, AnomalyDetector
from .embeddings import EmbeddingManager
from .data_processor import DataProcessor

class ModelTrainer:
    """Trains ML models for threat detection and anomaly identification"""
    
    def __init__(self, service_type: str, config: MLConfig = None):
        self.service_type = service_type
        self.config = config or MLConfig(service_type)
        self.feature_extractor = FeatureExtractor(service_type, self.config.to_dict())
        self.embedding_manager = EmbeddingManager(self.config)
        self.data_processor = DataProcessor()
        
        # Training results
        self.training_results = {}
        self.models = {}
        
    def prepare_training_data(self, data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Prepare data for training"""
        if not data:
            raise ValueError("No training data provided")
        
        # Extract labels
        labels = [item.get('label', 'normal') for item in data]
        
        # Extract features using batch processing
        text_vectors, numerical_scaled = self.feature_extractor.extract_batch_features(data)
        combined_features = self.feature_extractor.combine_features(text_vectors, numerical_scaled)
        
        # Extract text features for reference
        text_features = []
        for item in data:
            features = self.feature_extractor.extract_features(item)
            text_features.append(features.get('text_features', ''))
        
        return combined_features, np.array(labels), text_features
    
    def train_anomaly_detector(self, data: List[Dict[str, Any]], algorithm: str = 'isolation_forest') -> Dict[str, Any]:
        """Train anomaly detection model"""
        logging.info(f"Training {algorithm} anomaly detector for {self.service_type}")
        
        # Prepare data
        X, y, texts = self.prepare_training_data(data)
        
        # Validate data shapes
        if not isinstance(X, np.ndarray) or X.ndim != 2:
            raise ValueError(f"Invalid feature matrix shape: {X.shape if hasattr(X, 'shape') else type(X)}")
        
        if not isinstance(y, np.ndarray) or y.ndim != 1:
            raise ValueError(f"Invalid label array shape: {y.shape if hasattr(y, 'shape') else type(y)}")
        
        logging.info(f"Training data: X shape {X.shape}, y shape {y.shape}")
        
        # Filter normal data for unsupervised training
        normal_mask = (y == 'normal')
        X_normal = X[normal_mask]
        
        min_samples = max(10, min(50, len(X) // 10))  # Adaptive minimum: 10-50 samples or 10% of data
        
        if len(X_normal) < min_samples:
            logging.warning(f"Only {len(X_normal)} normal samples available, using all data for training")
            # If insufficient normal samples, use all data (treat as semi-supervised)
            X_normal = X
        
        logging.info(f"Using {len(X_normal)} samples for {algorithm} training")
        
        # Final validation before training
        if not isinstance(X_normal, np.ndarray):
            raise ValueError(f"X_normal must be numpy array, got {type(X_normal)}")
        if X_normal.ndim != 2:
            raise ValueError(f"X_normal must be 2D array, got shape {X_normal.shape}")
        if X_normal.size == 0:
            raise ValueError("X_normal is empty")
        
        logging.info(f"Training {algorithm} with data shape: {X_normal.shape}, dtype: {X_normal.dtype}")
        
        # Train model
        if algorithm == 'isolation_forest':
            model = self._train_isolation_forest(X_normal)
        elif algorithm == 'one_class_svm':
            model = self._train_one_class_svm(X_normal)
        elif algorithm == 'lof':
            model = self._train_lof(X_normal)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        # Evaluate on full dataset
        predictions = model.predict(X)
        scores = model.decision_function(X) if hasattr(model, 'decision_function') else predictions
        
        # Calculate metrics
        y_binary = (y != 'normal').astype(int)
        pred_binary = (predictions == -1).astype(int)
        
        results = {
            'algorithm': algorithm,
            'model_type': type(model).__name__,
            'accuracy': float(np.mean(y_binary == pred_binary)),
            'precision': float(self._calculate_precision(y_binary, pred_binary)),
            'recall': float(self._calculate_recall(y_binary, pred_binary)),
            'f1_score': float(self._calculate_f1(y_binary, pred_binary)),
            'normal_samples': int(len(X_normal)),
            'total_samples': int(len(X)),
            'anomaly_rate': float(np.mean(pred_binary))
        }
        
        self.models[f'{algorithm}_anomaly'] = model
        self.training_results[f'{algorithm}_anomaly'] = results
        
        logging.info(f"Anomaly detector trained - Accuracy: {results['accuracy']:.3f}, F1: {results['f1_score']:.3f}")
        
        return results
    
    def train_supervised_classifier(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train supervised classifier for threat severity"""
        logging.info(f"Training supervised classifier for {self.service_type}")
        
        # Prepare data
        X, y, texts = self.prepare_training_data(data)
        
        # Encode labels
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Train XGBoost classifier
        # Set default parameters
        default_params = {
            'n_estimators': 100,
            'max_depth': 6,
            'learning_rate': 0.1,
            'random_state': 42
        }
        model = xgb.XGBClassifier(
            **default_params,
            eval_metric='mlogloss'
        )
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)
        
        # Calculate metrics
        accuracy = np.mean(y_test == y_pred)
        
        # Multi-class ROC AUC
        try:
            auc_score = roc_auc_score(y_test, y_pred_proba, multi_class='ovr')
        except:
            auc_score = 0.0
        
        results = {
            'algorithm': 'xgboost',
            'model_type': type(model).__name__,
            'accuracy': float(accuracy),
            'auc_score': float(auc_score),
            'classes': label_encoder.classes_.tolist(),
            'feature_importance': model.feature_importances_.tolist() if hasattr(model, 'feature_importances_') else [],
            'train_samples': int(len(X_train)),
            'test_samples': int(len(X_test))
        }
        
        self.models['supervised_classifier'] = model
        self.models['label_encoder'] = label_encoder
        self.training_results['supervised_classifier'] = results
        
        logging.info(f"Supervised classifier trained - Accuracy: {accuracy:.3f}, AUC: {auc_score:.3f}")
        
        return results
    
    def train_clustering_model(self, data: List[Dict[str, Any]], algorithm: str = 'hdbscan') -> Dict[str, Any]:
        """Train clustering model for behavior grouping"""
        logging.info(f"Training {algorithm} clustering model for {self.service_type}")
        
        # Prepare data
        X, y, texts = self.prepare_training_data(data)
        
        # Train clustering model
        if algorithm == 'hdbscan' and HDBSCAN_AVAILABLE:
            model = self._train_hdbscan(X)
        elif algorithm == 'dbscan':
            model = self._train_dbscan(X)
        elif algorithm == 'kmeans':
            model = self._train_kmeans(X)
        else:
            raise ValueError(f"Unknown or unavailable algorithm: {algorithm}")
        
        # Get cluster labels
        if hasattr(model, 'labels_'):
            cluster_labels = model.labels_
        else:
            cluster_labels = model.predict(X)
        
        # Analyze clusters
        unique_clusters = np.unique(cluster_labels)
        cluster_info = {}
        
        for cluster_id in unique_clusters:
            if cluster_id == -1:  # Noise points
                continue
                
            cluster_mask = cluster_labels == cluster_id
            cluster_texts = [texts[i] for i in range(len(texts)) if cluster_mask[i]]
            cluster_labels_subset = y[cluster_mask]
            
            cluster_info[int(cluster_id)] = {
                'size': int(np.sum(cluster_mask)),
                'sample_texts': cluster_texts[:5],  # First 5 examples
                'label_distribution': {
                    label: int(np.sum(cluster_labels_subset == label))
                    for label in np.unique(cluster_labels_subset)
                }
            }
        
        results = {
            'algorithm': algorithm,
            'model_type': type(model).__name__,
            'n_clusters': int(len(unique_clusters) - (1 if -1 in unique_clusters else 0)),
            'n_noise': int(np.sum(cluster_labels == -1)),
            'cluster_info': cluster_info,
            'silhouette_score': float(self._calculate_silhouette_score(X, cluster_labels))
        }
        
        self.models[f'{algorithm}_clustering'] = model
        self.training_results[f'{algorithm}_clustering'] = results
        
        logging.info(f"Clustering model trained - Clusters: {results['n_clusters']}, Noise: {results['n_noise']}")
        
        return results
    
    def train_embedding_similarity(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train embedding-based similarity detection"""
        logging.info(f"Training embedding similarity for {self.service_type}")
        
        # Extract text features
        texts = []
        for item in data:
            features = self.feature_extractor.extract_features(item)
            texts.append(features.get('text_features', ''))
        
        # Build FAISS index
        self.embedding_manager.build_faiss_index(texts, force_rebuild=True)
        
        # Test similarity detection
        sample_size = min(100, len(texts))
        sample_indices = np.random.choice(len(texts), sample_size, replace=False)
        
        similarity_scores = []
        for idx in sample_indices:
            query_text = texts[idx]
            similar_texts = self.embedding_manager.find_similar(query_text, k=5)
            
            if similar_texts:
                max_similarity = max(score for _, score in similar_texts[1:])  # Exclude self
                similarity_scores.append(max_similarity)
        
        results = {
            'algorithm': 'sentence_transformers',
            'total_texts': len(texts),
            'index_size': self.embedding_manager.faiss_index.ntotal if self.embedding_manager.faiss_index else 0,
            'avg_similarity': np.mean(similarity_scores) if similarity_scores else 0.0,
            'similarity_std': np.std(similarity_scores) if similarity_scores else 0.0,
            'embedding_model': self.config.get_embedding_model()
        }
        
        self.training_results['embedding_similarity'] = results
        
        logging.info(f"Embedding similarity trained - Index size: {results['index_size']}")
        
        return results
    
    def train_all_models(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train all available models"""
        logging.info(f"Training all models for {self.service_type} with {len(data)} samples")
        
        all_results = {}
        
        try:
            # Anomaly detection
            all_results['isolation_forest'] = self.train_anomaly_detector(data, 'isolation_forest')
        except Exception as e:
            logging.error(f"Failed to train isolation forest: {e}")
        
        try:
            all_results['one_class_svm'] = self.train_anomaly_detector(data, 'one_class_svm')
        except Exception as e:
            logging.error(f"Failed to train one-class SVM: {e}")
        
        try:
            # Supervised classification (if multiple labels exist)
            labels = [item.get('label', 'normal') for item in data]
            if len(set(labels)) > 1:
                all_results['supervised'] = self.train_supervised_classifier(data)
        except Exception as e:
            logging.error(f"Failed to train supervised classifier: {e}")
        
        try:
            # Clustering
            if HDBSCAN_AVAILABLE:
                all_results['hdbscan'] = self.train_clustering_model(data, 'hdbscan')
            else:
                all_results['kmeans'] = self.train_clustering_model(data, 'kmeans')
        except Exception as e:
            logging.error(f"Failed to train clustering model: {e}")
        
        try:
            # Embedding similarity
            all_results['embeddings'] = self.train_embedding_similarity(data)
        except Exception as e:
            logging.error(f"Failed to train embedding similarity: {e}")
        
        return all_results
    
    def save_models(self):
        """Save all trained models"""
        for model_name, model in self.models.items():
            try:
                model_path = self.config.get_model_path(model_name, self.service_type)
                joblib.dump(model, model_path)
                logging.info(f"Saved {model_name} to {model_path}")
            except Exception as e:
                logging.error(f"Failed to save {model_name}: {e}")
        
        # Save feature extractor components
        try:
            if self.feature_extractor.vectorizer:
                vectorizer_path = self.config.get_vectorizer_path(self.service_type)
                joblib.dump(self.feature_extractor.vectorizer, vectorizer_path)
            
            if self.feature_extractor.scaler:
                scaler_path = self.config.get_model_path('scaler', self.service_type)
                joblib.dump(self.feature_extractor.scaler, scaler_path)
                
        except Exception as e:
            logging.error(f"Failed to save feature extractor components: {e}")
    
    def evaluate_model(self, model_name: str, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate a trained model on test data"""
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")
        
        model = self.models[model_name]
        X_test, y_test, texts = self.prepare_training_data(test_data)
        
        # Make predictions
        if 'anomaly' in model_name:
            predictions = model.predict(X_test)
            y_binary = (y_test != 'normal').astype(int)
            pred_binary = (predictions == -1).astype(int)
            
            return {
                'model_name': model_name,
                'test_samples': int(len(X_test)),
                'accuracy': float(np.mean(y_binary == pred_binary)),
                'precision': float(self._calculate_precision(y_binary, pred_binary)),
                'recall': float(self._calculate_recall(y_binary, pred_binary)),
                'f1_score': float(self._calculate_f1(y_binary, pred_binary))
            }
        
        elif model_name == 'supervised_classifier':
            label_encoder = self.models['label_encoder']
            y_encoded = label_encoder.transform(y_test)
            predictions = model.predict(X_test)
            
            return {
                'model_name': model_name,
                'test_samples': int(len(X_test)),
                'accuracy': float(np.mean(y_encoded == predictions)),
                'classification_report': classification_report(y_encoded, predictions, output_dict=True)
            }
        
        elif 'clustering' in model_name:
            # For clustering models, evaluate cluster quality
            cluster_labels = model.fit_predict(X_test)
            return {
                'model_name': model_name,
                'test_samples': int(len(X_test)),
                'n_clusters': int(len(np.unique(cluster_labels[cluster_labels != -1]))),
                'n_noise': int(np.sum(cluster_labels == -1)),
                'silhouette_score': float(self._calculate_silhouette_score(X_test, cluster_labels))
            }
        
        return {
            'model_name': model_name,
            'test_samples': int(len(X_test)),
            'status': 'evaluation_not_implemented'
        }
    
    # Helper methods for training specific algorithms
    def _train_isolation_forest(self, X: np.ndarray) -> IsolationForest:
        logging.info(f"IsolationForest training with X shape: {X.shape}, dtype: {X.dtype}")
        # Set default parameters
        default_params = {'contamination': 0.1, 'random_state': 42}
        model = IsolationForest(**default_params)
        model.fit(X)
        return model
    
    def _train_one_class_svm(self, X: np.ndarray) -> OneClassSVM:
        # Set default parameters
        default_params = {'gamma': 'scale', 'nu': 0.1}
        model = OneClassSVM(**default_params)
        model.fit(X)
        return model
    
    def _train_lof(self, X: np.ndarray) -> LocalOutlierFactor:
        # Set default parameters
        default_params = {'n_neighbors': 20, 'contamination': 0.1}
        model = LocalOutlierFactor(novelty=True, **default_params)
        model.fit(X)
        return model
    
    def _train_hdbscan(self, X: np.ndarray):
        # Set default parameters
        default_params = {'min_cluster_size': 5, 'min_samples': 3}
        model = hdbscan.HDBSCAN(**default_params)
        model.fit(X)
        return model
    
    def _train_dbscan(self, X: np.ndarray) -> DBSCAN:
        model = DBSCAN(eps=0.5, min_samples=5)
        model.fit(X)
        return model
    
    def _train_kmeans(self, X: np.ndarray) -> KMeans:
        # Determine optimal number of clusters
        n_clusters = min(8, max(2, len(X) // 50))
        model = KMeans(n_clusters=n_clusters, random_state=42)
        model.fit(X)
        return model
    
    # Helper methods for metrics calculation
    def _calculate_precision(self, y_true: np.ndarray, y_pred: np.ndarray) -> float:
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0
    
    def _calculate_recall(self, y_true: np.ndarray, y_pred: np.ndarray) -> float:
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fn = np.sum((y_true == 1) & (y_pred == 0))
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    def _calculate_f1(self, y_true: np.ndarray, y_pred: np.ndarray) -> float:
        precision = self._calculate_precision(y_true, y_pred)
        recall = self._calculate_recall(y_true, y_pred)
        return 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    def _calculate_silhouette_score(self, X: np.ndarray, labels: np.ndarray) -> float:
        try:
            from sklearn.metrics import silhouette_score
            # Filter out noise points (-1 labels)
            mask = labels != -1
            if np.sum(mask) < 2 or len(np.unique(labels[mask])) < 2:
                return 0.0
            return silhouette_score(X[mask], labels[mask])
        except:
            return 0.0
