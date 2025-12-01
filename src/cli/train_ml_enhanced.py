#!/usr/bin/env python3
"""
ML Training with Progress Tracking
Wrapper script for training ML models with detailed progress output
"""

import sys
import argparse
from pathlib import Path

# Add src directory to path
src_dir = Path(__file__).parent.parent
sys.path.insert(0, str(src_dir))

from ai.training_enhanced import EnhancedModelTrainer
from ai.data_processor import DataProcessor

def main():
    parser = argparse.ArgumentParser(description='Train ML models with progress tracking')
    parser.add_argument('service', choices=['ssh', 'http', 'ftp', 'mysql', 'smb', 'all'],
                       help='Service to train models for')
    parser.add_argument('--algorithm', choices=['isolation_forest', 'one_class_svm', 'lof', 'hdbscan', 'kmeans', 'xgboost', 'all'],
                       default='all', help='ML algorithm to train')
    parser.add_argument('--data', help='Training data file path')
    parser.add_argument('--test-size', type=float, default=0.2, help='Test set size (0.0-1.0)')
    
    args = parser.parse_args()
    
    print("[INFO] ML Training with Enhanced Progress Tracking")
    print("=" * 60)
    print(f"Service: {args.service}")
    print(f"Algorithm: {args.algorithm}")
    print("=" * 60)
    print()
    
    if args.service == 'all':
        services = ['ssh', 'http', 'ftp', 'mysql', 'smb']
    else:
        services = [args.service]
    
    processor = DataProcessor()
    
    for service in services:
        print(f"\n{'='*60}")
        print(f"Training models for {service.upper()}")
        print(f"{'='*60}\n")
        
        try:
            trainer = EnhancedModelTrainer(service, verbose=True)
            
            # Get training data
            if args.data:
                import json
                import numpy as np
                with open(args.data, 'r') as f:
                    all_data = json.load(f)
                    np.random.shuffle(all_data)
                    split_idx = int(len(all_data) * (1 - args.test_size))
                    train_data = all_data[:split_idx]
            else:
                train_data, _ = processor.get_training_data(service, args.test_size)
            
            if not train_data:
                print(f"[WARNING] No training data available for {service}")
                continue
            
            print(f"[INFO] Training with {len(train_data)} samples\n")
            
            # Train models
            if args.algorithm == 'all':
                results = trainer.train_all_models(train_data)
            else:
                if args.algorithm in ['isolation_forest', 'one_class_svm', 'lof']:
                    results = {args.algorithm: trainer.train_anomaly_detector(train_data, args.algorithm)}
                elif args.algorithm == 'xgboost':
                    results = {args.algorithm: trainer.train_supervised_classifier(train_data)}
                elif args.algorithm in ['hdbscan', 'kmeans']:
                    results = {args.algorithm: trainer.train_clustering_model(train_data, args.algorithm)}
            
            # Save models
            print("\n[INFO] Saving trained models...")
            trainer.save_models()
            
            # Print results summary
            print(f"\n[SUCCESS] Training completed for {service.upper()}")
            print("\n[SUMMARY] Results Summary:")
            for algo, result in results.items():
                accuracy = result.get('accuracy', 'N/A')
                if isinstance(accuracy, (int, float)):
                    print(f"  {algo}: {accuracy:.3f} accuracy")
                else:
                    print(f"  {algo}: {accuracy}")
            
        except Exception as e:
            print(f"[ERROR] Error training {service}: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*60}")
    print("[SUCCESS] All training complete!")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
