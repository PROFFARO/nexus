"""
Model Training for NEXUS AI - Train and evaluate ML models for threat detection
With comprehensive logging and verbose output for ML operations.
"""

import numpy as np
import pandas as pd
import joblib
import logging
import time
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
from .ml_logger import get_ml_logger, VerbosityLevel

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
        
        # Verbosity and logging
        self.verbosity = VerbosityLevel.NORMAL
        self.ml_logger = None
        
    def set_verbosity(self, level: int):
        """Set verbosity level for training operations"""
        self.verbosity = level
        self.ml_logger = get_ml_logger(level, self.service_type)
        
    def _get_logger(self):
        """Get ML logger instance"""
        if self.ml_logger is None:
            self.ml_logger = get_ml_logger(self.verbosity, self.service_type)
        return self.ml_logger
        
    def prepare_training_data(self, data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Prepare data for training"""
        logger = self._get_logger()
        prep_start = time.time()
        
        if not data:
            raise ValueError("No training data provided")
        
        # Extract labels
        labels = [item.get('label', 'normal') for item in data]
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Preparing {len(data):,} samples for training...", level="debug")
        
        try:
            # Extract features using batch processing
            if self.verbosity >= VerbosityLevel.DEBUG:
                logger.log_step("Extracting text and numerical features...", level="debug", indent=2)
            
            extract_start = time.time()
            text_vectors, numerical_scaled = self.feature_extractor.extract_batch_features(data)
            extract_time = time.time() - extract_start
            
            if self.verbosity >= VerbosityLevel.DEBUG:
                logger.log_step(f"Text vectors: {text_vectors.shape if hasattr(text_vectors, 'shape') else 'N/A'}", level="debug", indent=2)
                logger.log_step(f"Numerical features: {numerical_scaled.shape if hasattr(numerical_scaled, 'shape') else 'N/A'}", level="debug", indent=2)
            
            combined_features = self.feature_extractor.combine_features(text_vectors, numerical_scaled)
            
            # Validate combined features
            if not isinstance(combined_features, np.ndarray):
                logging.error(f"Combined features is not numpy array: {type(combined_features)}")
                raise ValueError(f"Invalid combined features type: {type(combined_features)}")
            
            if combined_features.ndim != 2:
                logging.error(f"Combined features has wrong dimensions: {combined_features.ndim}")
                combined_features = combined_features.reshape(-1, 1) if combined_features.ndim == 1 else np.zeros((len(data), 1))
            
            if combined_features.shape[0] != len(data):
                logging.error(f"Feature count mismatch: {combined_features.shape[0]} vs {len(data)}")
                # Pad or truncate to match
                if combined_features.shape[0] < len(data):
                    padding = np.zeros((len(data) - combined_features.shape[0], combined_features.shape[1]))
                    combined_features = np.vstack([combined_features, padding])
                else:
                    combined_features = combined_features[:len(data)]
            
            # Extract text features for reference
            text_features = []
            for item in data:
                features = self.feature_extractor.extract_features(item)
                text_features.append(str(features.get('text_features', '')))
            
            prep_time = time.time() - prep_start
            
            if self.verbosity >= VerbosityLevel.VERBOSE:
                logger.log_step(
                    f"Prepared: {combined_features.shape} features, {len(labels)} labels ({prep_time:.2f}s)",
                    level="data"
                )
            
            logging.info(f"Prepared training data: {combined_features.shape} features, {len(labels)} labels")
            return combined_features, np.array(labels), text_features
            
        except Exception as e:
            logger.log_error(f"Error preparing training data", exception=e)
            logging.error(f"Error preparing training data: {e}")
            # Fallback: create minimal feature matrix
            fallback_features = np.zeros((len(data), 1))
            text_features = [str(item.get('text_features', '')) for item in data]
            return fallback_features, np.array(labels), text_features

    
    def train_anomaly_detector(self, data: List[Dict[str, Any]], algorithm: str = 'isolation_forest') -> Dict[str, Any]:
        """Train anomaly detection model"""
        logger = self._get_logger()
        train_start = time.time()
        
        logging.info(f"Training {algorithm} anomaly detector for {self.service_type}")
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Initializing {algorithm} training...", level="info")
            logger.log_step(f"Input samples: {len(data):,}", level="data", indent=2)
        
        # Prepare data
        X, y, texts = self.prepare_training_data(data)
        
        # Validate data shapes
        if not isinstance(X, np.ndarray):
            logging.error(f"X is not numpy array: {type(X)}")
            raise ValueError(f"Invalid feature matrix type: {type(X)}")
            
        if X.ndim != 2:
            logging.error(f"X has wrong dimensions: {X.ndim}, shape: {X.shape}")
            if X.ndim == 1:
                X = X.reshape(-1, 1)
            else:
                raise ValueError(f"Cannot reshape X with {X.ndim} dimensions")
        
        if not isinstance(y, np.ndarray):
            logging.error(f"y is not numpy array: {type(y)}")
            y = np.array(y)
            
        if y.ndim != 1:
            logging.error(f"y has wrong dimensions: {y.ndim}, shape: {y.shape}")
            if y.ndim == 0:
                y = y.reshape(1)
            else:
                y = y.flatten()
        
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
            logging.error(f"X_normal is not numpy array: {type(X_normal)}")
            raise ValueError(f"X_normal must be numpy array, got {type(X_normal)}")
            
        if X_normal.ndim != 2:
            logging.error(f"X_normal wrong dimensions: {X_normal.ndim}, shape: {X_normal.shape}")
            if X_normal.ndim == 1:
                X_normal = X_normal.reshape(-1, 1)
            else:
                raise ValueError(f"X_normal must be 2D array, got shape {X_normal.shape}")
                
        if X_normal.size == 0:
            logging.error("X_normal is empty")
            raise ValueError("X_normal is empty")
            
        if X_normal.shape[1] == 0:
            logging.error("X_normal has 0 features")
            X_normal = np.ones((X_normal.shape[0], 1))  # Add dummy feature
        
        logging.info(f"Training {algorithm} with data shape: {X_normal.shape}, dtype: {X_normal.dtype}")
        
        # Train model
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Training {algorithm} model...", level="info", indent=2)
            
        model_train_start = time.time()
        
        if algorithm == 'isolation_forest':
            model = self._train_isolation_forest(X_normal)
        elif algorithm == 'one_class_svm':
            model = self._train_one_class_svm(X_normal)
        elif algorithm == 'lof':
            model = self._train_lof(X_normal)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        model_train_time = time.time() - model_train_start
        
        if self.verbosity >= VerbosityLevel.DEBUG:
            logger.log_step(f"Model trained in {model_train_time:.2f}s", level="debug", indent=2)
        
        # Evaluate on full dataset
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step("Evaluating on full dataset...", level="info", indent=2)
            
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
            'anomaly_rate': float(np.mean(pred_binary)),
            'training_time': model_train_time
        }
        
        self.models[f'{algorithm}_anomaly'] = model
        self.training_results[f'{algorithm}_anomaly'] = results
        
        total_train_time = time.time() - train_start
        
        # Display verbose metrics
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_metrics({
                'Accuracy': results['accuracy'],
                'Precision': results['precision'],
                'Recall': results['recall'],
                'F1 Score': results['f1_score'],
                'Anomaly Rate': results['anomaly_rate']
            }, title=f"{algorithm} Metrics", indent=2)
            logger.log_step(f"Total training time: {total_train_time:.2f}s", level="timing" if hasattr(logger, 'log_step') else "info", indent=2)
        
        logging.info(f"Anomaly detector trained - Accuracy: {results['accuracy']:.3f}, F1: {results['f1_score']:.3f}")
        
        return results
    
    def train_supervised_classifier(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train supervised classifier for threat severity"""
        logger = self._get_logger()
        train_start = time.time()
        
        logging.info(f"Training supervised classifier for {self.service_type}")
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Initializing XGBoost classifier training...", level="info")
            logger.log_step(f"Input samples: {len(data):,}", level="data", indent=2)
        
        # Prepare data
        X, y, texts = self.prepare_training_data(data)
        
        # Encode labels
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Classes found: {len(label_encoder.classes_)} - {list(label_encoder.classes_)}", level="data", indent=2)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Train/test split: {len(X_train):,} / {len(X_test):,}", level="data", indent=2)
        
        # Train XGBoost classifier
        # Set default parameters
        default_params = {
            'n_estimators': 100,
            'max_depth': 6,
            'learning_rate': 0.1,
            'random_state': 42
        }
        
        if self.verbosity >= VerbosityLevel.DEBUG:
            logger.log_model_params("XGBClassifier", default_params)
        
        model = xgb.XGBClassifier(
            **default_params,
            eval_metric='mlogloss'
        )
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step("Training XGBoost classifier...", level="info", indent=2)
        
        model_train_start = time.time()
        model.fit(X_train, y_train)
        model_train_time = time.time() - model_train_start
        
        if self.verbosity >= VerbosityLevel.DEBUG:
            logger.log_step(f"Model trained in {model_train_time:.2f}s", level="debug", indent=2)
        
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
            'test_samples': int(len(X_test)),
            'training_time': model_train_time
        }
        
        self.models['supervised_classifier'] = model
        self.models['label_encoder'] = label_encoder
        self.training_results['supervised_classifier'] = results
        
        total_train_time = time.time() - train_start
        
        # Display verbose metrics
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_metrics({
                'Accuracy': results['accuracy'],
                'AUC Score': results['auc_score'],
                'Classes': len(results['classes']),
                'Train Samples': results['train_samples'],
                'Test Samples': results['test_samples']
            }, title="XGBoost Metrics", indent=2)
            logger.log_step(f"Total training time: {total_train_time:.2f}s", level="info", indent=2)
        
        logging.info(f"Supervised classifier trained - Accuracy: {accuracy:.3f}, AUC: {auc_score:.3f}")
        
        return results
    
    def train_clustering_model(self, data: List[Dict[str, Any]], algorithm: str = 'hdbscan') -> Dict[str, Any]:
        """Train clustering model for behavior grouping"""
        logger = self._get_logger()
        train_start = time.time()
        
        logging.info(f"Training {algorithm} clustering model for {self.service_type}")
        
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Initializing {algorithm} clustering...", level="info")
            logger.log_step(f"Input samples: {len(data):,}", level="data", indent=2)
        
        # Prepare data
        X, y, texts = self.prepare_training_data(data)
        
        # Train clustering model
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_step(f"Training {algorithm} model...", level="info", indent=2)
        
        model_train_start = time.time()
        
        if algorithm == 'hdbscan' and HDBSCAN_AVAILABLE:
            model = self._train_hdbscan(X)
        elif algorithm == 'dbscan':
            model = self._train_dbscan(X)
        elif algorithm == 'kmeans':
            model = self._train_kmeans(X)
        else:
            raise ValueError(f"Unknown or unavailable algorithm: {algorithm}")
        
        model_train_time = time.time() - model_train_start
        
        if self.verbosity >= VerbosityLevel.DEBUG:
            logger.log_step(f"Model trained in {model_train_time:.2f}s", level="debug", indent=2)
        
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
            'silhouette_score': float(self._calculate_silhouette_score(X, cluster_labels)),
            'training_time': model_train_time
        }
        
        self.models[f'{algorithm}_clustering'] = model
        self.training_results[f'{algorithm}_clustering'] = results
        
        total_train_time = time.time() - train_start
        
        # Display verbose metrics
        if self.verbosity >= VerbosityLevel.VERBOSE:
            logger.log_metrics({
                'Clusters': results['n_clusters'],
                'Noise Points': results['n_noise'],
                'Silhouette Score': results['silhouette_score']
            }, title=f"{algorithm} Clustering Metrics", indent=2)
            
            if self.verbosity >= VerbosityLevel.DEBUG and cluster_info:
                logger.log_step("Cluster sizes:", level="debug", indent=2)
                for cid, info in list(cluster_info.items())[:5]:  # Show first 5 clusters
                    logger.log_step(f"  Cluster {cid}: {info['size']} samples", level="debug", indent=3)
        
        logging.info(f"Clustering model trained - Clusters: {results['n_clusters']}, Noise: {results['n_noise']}")
        
        return results
    
    def train_embedding_similarity(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train embedding-based similarity detection"""
        logging.info(f"Training embedding similarity for {self.service_type}")
        
        try:
            # Extract text features
            texts = []
            for item in data:
                try:
                    features = self.feature_extractor.extract_features(item)
                    text_feature = features.get('text_features', '')
                    # Ensure text is string and not empty
                    if isinstance(text_feature, str) and text_feature.strip():
                        texts.append(text_feature)
                    elif text_feature:  # Convert non-string to string
                        texts.append(str(text_feature))
                    else:
                        texts.append("empty")  # Default for empty features
                except Exception as e:
                    logging.warning(f"Failed to extract features for item: {e}")
                    texts.append("empty")
            
            if not texts:
                logging.error("No valid text features extracted")
                return {
                    'algorithm': 'sentence_transformers',
                    'total_texts': 0,
                    'index_size': 0,
                    'avg_similarity': 0.0,
                    'similarity_std': 0.0,
                    'embedding_model': self.config.get_embedding_model(),
                    'error': 'No valid text features'
                }
            
            logging.info(f"Extracted {len(texts)} text features for embedding training")
            
            # Build FAISS index
            try:
                self.embedding_manager.build_faiss_index(texts, force_rebuild=True)
            except Exception as e:
                logging.error(f"Failed to build FAISS index: {e}")
                return {
                    'algorithm': 'sentence_transformers',
                    'total_texts': len(texts),
                    'index_size': 0,
                    'avg_similarity': 0.0,
                    'similarity_std': 0.0,
                    'embedding_model': self.config.get_embedding_model(),
                    'error': f'FAISS index build failed: {str(e)}'
                }
            
            # Test similarity detection
            similarity_scores = []
            if len(texts) > 1:  # Need at least 2 texts for similarity
                sample_size = min(100, len(texts))
                try:
                    sample_indices = np.random.choice(len(texts), sample_size, replace=False)
                    
                    for idx in sample_indices:
                        try:
                            query_text = texts[idx]
                            if not isinstance(query_text, str) or not query_text.strip():
                                continue
                                
                            similar_texts = self.embedding_manager.find_similar(query_text, k=5)
                            
                            if similar_texts and len(similar_texts) > 1:
                                # Exclude self (first result) and get max similarity from remaining
                                remaining_scores = [score for _, score in similar_texts[1:] if isinstance(score, (int, float))]
                                if remaining_scores:
                                    max_similarity = max(remaining_scores)
                                    similarity_scores.append(max_similarity)
                        except Exception as e:
                            logging.warning(f"Failed similarity test for text {idx}: {e}")
                            continue
                            
                except Exception as e:
                    logging.warning(f"Failed to run similarity tests: {e}")
            
            results = {
                'algorithm': 'sentence_transformers',
                'total_texts': len(texts),
                'index_size': self.embedding_manager.faiss_index.ntotal if self.embedding_manager.faiss_index else 0,
                'avg_similarity': float(np.mean(similarity_scores)) if similarity_scores else 0.0,
                'similarity_std': float(np.std(similarity_scores)) if similarity_scores else 0.0,
                'embedding_model': self.config.get_embedding_model()
            }
            
            self.training_results['embedding_similarity'] = results
            
            logging.info(f"Embedding similarity trained - Index size: {results['index_size']}")
            
            return results
            
        except Exception as e:
            logging.error(f"Failed to train embedding similarity: {e}")
            return {
                'algorithm': 'sentence_transformers',
                'total_texts': 0,
                'index_size': 0,
                'avg_similarity': 0.0,
                'similarity_std': 0.0,
                'embedding_model': self.config.get_embedding_model() if hasattr(self.config, 'get_embedding_model') else 'unknown',
                'error': str(e)
            }
    
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
        
        # Validate input
        if not isinstance(X, np.ndarray) or X.ndim != 2 or X.size == 0:
            raise ValueError(f"Invalid input for IsolationForest: shape {X.shape if hasattr(X, 'shape') else 'unknown'}")
        
        # Set default parameters
        default_params = {'contamination': 0.1, 'random_state': 42}
        model = IsolationForest(**default_params)
        
        try:
            model.fit(X)
            return model
        except Exception as e:
            logging.error(f"IsolationForest training failed: {e}")
            raise
    
    def _train_one_class_svm(self, X: np.ndarray) -> OneClassSVM:
        logging.info(f"OneClassSVM training with X shape: {X.shape}, dtype: {X.dtype}")
        
        # Validate input
        if not isinstance(X, np.ndarray) or X.ndim != 2 or X.size == 0:
            raise ValueError(f"Invalid input for OneClassSVM: shape {X.shape if hasattr(X, 'shape') else 'unknown'}")
        
        # Set default parameters
        default_params = {'gamma': 'scale', 'nu': 0.1}
        model = OneClassSVM(**default_params)
        
        try:
            model.fit(X)
            return model
        except Exception as e:
            logging.error(f"OneClassSVM training failed: {e}")
            raise
    
    def _train_lof(self, X: np.ndarray) -> LocalOutlierFactor:
        # Set default parameters
        default_params = {'n_neighbors': 20, 'contamination': 0.1}
        model = LocalOutlierFactor(novelty=True, **default_params)
        model.fit(X)
        return model
    
    def _train_hdbscan(self, X: np.ndarray):
        logging.info(f"HDBSCAN training with X shape: {X.shape}, dtype: {X.dtype}")
        
        # Validate input
        if not isinstance(X, np.ndarray) or X.ndim != 2 or X.size == 0:
            raise ValueError(f"Invalid input for HDBSCAN: shape {X.shape if hasattr(X, 'shape') else 'unknown'}")
        
        # Set default parameters
        default_params = {'min_cluster_size': 5, 'min_samples': 3}
        model = hdbscan.HDBSCAN(**default_params)
        
        try:
            model.fit(X)
            return model
        except Exception as e:
            logging.error(f"HDBSCAN training failed: {e}")
            raise
    
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
