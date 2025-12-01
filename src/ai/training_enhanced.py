"""
Enhanced ML Training with Progress Tracking and Debugging
Wraps existing ModelTrainer with comprehensive progress monitoring
"""

import time
import logging
from typing import Dict, List, Any
from pathlib import Path

# Progress tracking
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("[WARNING] tqdm not available - install with: pip install tqdm")

# Resource monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[WARNING] psutil not available - install with: pip install psutil")

from .training import ModelTrainer as BaseModelTrainer


class EnhancedModelTrainer(BaseModelTrainer):
    """Enhanced ModelTrainer with progress tracking and debugging"""
    
    def __init__(self, service_type: str, config=None, verbose: bool = True):
        super().__init__(service_type, config)
        self.verbose = verbose
        self.start_time = None
        self.operation_times = {}
        
        # Resource monitoring
        if PSUTIL_AVAILABLE:
            self.process = psutil.Process()
            self.initial_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        else:
            self.process = None
            self.initial_memory = 0
    
    def _log_progress(self, message: str, level: str = 'info'):
        """Log progress with timestamp and resource usage"""
        timestamp = time.strftime('%H:%M:%S')
        
        # Add memory usage if available
        if PSUTIL_AVAILABLE and self.process:
            current_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            memory_delta = current_memory - self.initial_memory
            message = f"[{timestamp}] {message} (Memory: {current_memory:.1f}MB, +{memory_delta:.1f}MB)"
        else:
            message = f"[{timestamp}] {message}"
        
        if level == 'info':
            logging.info(message)
            if self.verbose:
                print(f"[INFO] {message}")
        elif level == 'warning':
            logging.warning(message)
            if self.verbose:
                print(f"[WARNING] {message}")
        elif level == 'error':
            logging.error(message)
            if self.verbose:
                print(f"[ERROR] {message}")
    
    def _start_timer(self, operation: str):
        """Start timing an operation"""
        self.start_time = time.time()
        self._log_progress(f"Starting: {operation}")
    
    def _end_timer(self, operation: str):
        """End timing and log duration"""
        if self.start_time:
            duration = time.time() - self.start_time
            self.operation_times[operation] = duration
            self._log_progress(f"Completed: {operation} in {duration:.2f}s")
            self.start_time = None
            return duration
        return 0
    
    def prepare_training_data(self, data: List[Dict[str, Any]]):
        """Prepare training data with progress tracking"""
        self._start_timer(f"Data preparation ({len(data)} samples)")
        self._log_progress(f"Extracting features from {len(data)} samples...")
        
        try:
            result = super().prepare_training_data(data)
            self._log_progress(f"Feature extraction successful: {result[0].shape} features")
            self._end_timer(f"Data preparation ({len(data)} samples)")
            return result
        except Exception as e:
            self._log_progress(f"Feature extraction failed: {e}", 'error')
            self._end_timer(f"Data preparation ({len(data)} samples) - FAILED")
            raise
    
    def train_anomaly_detector(self, data: List[Dict[str, Any]], algorithm: str = 'isolation_forest'):
        """Train anomaly detector with progress tracking"""
        self._start_timer(f"{algorithm} training")
        self._log_progress(f"Training {algorithm} on {len(data)} samples...")
        
        try:
            result = super().train_anomaly_detector(data, algorithm)
            self._log_progress(f"{algorithm} training complete - Accuracy: {result['accuracy']:.3f}")
            self._end_timer(f"{algorithm} training")
            return result
        except Exception as e:
            self._log_progress(f"{algorithm} training failed: {e}", 'error')
            self._end_timer(f"{algorithm} training - FAILED")
            raise
    
    def train_embedding_similarity(self, data: List[Dict[str, Any]]):
        """Train embedding similarity with progress tracking"""
        self._start_timer("Embedding similarity training")
        self._log_progress(f"Building embeddings for {len(data)} samples (this may take several minutes)...")
        
        try:
            result = super().train_embedding_similarity(data)
            self._log_progress(f"Embedding training complete - Index size: {result.get('index_size', 0)}")
            self._end_timer("Embedding similarity training")
            return result
        except Exception as e:
            self._log_progress(f"Embedding training failed: {e}", 'error')
            self._end_timer("Embedding similarity training - FAILED")
            raise
    
    def train_all_models(self, data: List[Dict[str, Any]]):
        """Train all models with comprehensive progress tracking"""
        self._start_timer(f"All models training ({len(data)} samples)")
        self._log_progress(f"Starting comprehensive training on {len(data)} samples...")
        
        all_results = {}
        models_to_train = [
            ('isolation_forest', 'Isolation Forest'),
            ('one_class_svm', 'One-Class SVM'),
            ('supervised', 'Supervised Classifier'),
            ('hdbscan', 'HDBSCAN Clustering'),
            ('embeddings', 'Embedding Similarity')
        ]
        
        for i, (model_key, model_name) in enumerate(models_to_train, 1):
            self._log_progress(f"[{i}/{len(models_to_train)}] Training {model_name}...")
            
            try:
                if model_key == 'isolation_forest':
                    all_results[model_key] = self.train_anomaly_detector(data, 'isolation_forest')
                elif model_key == 'one_class_svm':
                    all_results[model_key] = self.train_anomaly_detector(data, 'one_class_svm')
                elif model_key == 'supervised':
                    labels = [item.get('label', 'normal') for item in data]
                    if len(set(labels)) > 1:
                        all_results[model_key] = self.train_supervised_classifier(data)
                    else:
                        self._log_progress(f"Skipping {model_name} - only one label type", 'warning')
                elif model_key == 'hdbscan':
                    all_results[model_key] = self.train_clustering_model(data, 'hdbscan')
                elif model_key == 'embeddings':
                    all_results[model_key] = self.train_embedding_similarity(data)
                    
                self._log_progress(f"[SUCCESS] {model_name} completed successfully")
                
            except Exception as e:
                self._log_progress(f"[FAILED] {model_name} failed: {e}", 'warning')
                logging.exception(f"Detailed error for {model_name}")
        
        self._log_progress(f"Training summary: {len(all_results)}/{len(models_to_train)} models trained successfully")
        self._end_timer(f"All models training ({len(data)} samples)")
        
        # Print timing summary
        if self.verbose and self.operation_times:
            print("\n[SUMMARY] Training Time Summary:")
            for operation, duration in self.operation_times.items():
                print(f"  {operation}: {duration:.2f}s")
        
        return all_results
