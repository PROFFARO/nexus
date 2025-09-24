#!/usr/bin/env python3
"""
Simple ML Test - Direct testing without service dependencies
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

def test_ml_detector_direct():
    """Test MLDetector directly"""
    print("🔍 Testing MLDetector Direct Import")
    
    try:
        from ai.detectors import MLDetector
        print("✅ MLDetector imported successfully")
        
        # Test SSH detector
        print("\n🔍 Testing SSH ML Detector")
        ssh_detector = MLDetector('ssh')
        print(f"   Is Trained: {ssh_detector.is_trained}")
        
        if ssh_detector.is_trained:
            test_data = {
                'command': 'rm -rf /',
                'timestamp': '2025-01-25T02:15:00Z',
                'severity': 'high'
            }
            
            result = ssh_detector.score(test_data)
            print(f"   ✅ SSH ML Results:")
            print(f"      Anomaly Score: {result.get('ml_anomaly_score', 0):.3f}")
            print(f"      Labels: {result.get('ml_labels', [])}")
            print(f"      Confidence: {result.get('ml_confidence', 0):.3f}")
            print(f"      Inference Time: {result.get('ml_inference_time_ms', 0)}ms")
        else:
            print("   ❌ SSH detector not trained")
        
        return True
        
    except Exception as e:
        print(f"❌ MLDetector test failed: {e}")
        return False

def test_models_exist():
    """Test if model files exist"""
    print("\n🔍 Testing Model Files")
    
    models_dir = Path("models")
    services = ["ssh", "http", "ftp", "mysql", "smb"]
    
    for service in services:
        service_dir = models_dir / service
        if service_dir.exists():
            files = list(service_dir.glob("*.pkl")) + list(service_dir.glob("*.cache")) + list(service_dir.glob("*.index"))
            print(f"   ✅ {service.upper()}: {len(files)} model files found")
        else:
            print(f"   ❌ {service.upper()}: No models directory")

def main():
    print("🚀 Simple ML Integration Test")
    print("=" * 40)
    
    test_models_exist()
    test_ml_detector_direct()

if __name__ == "__main__":
    main()
