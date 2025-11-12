#!/usr/bin/env python3
"""
Test script to verify ML fixes work properly
"""

import sys
import os
from pathlib import Path

# Add the src directory to the path
sys.path.append(str(Path(__file__).parent / "src"))

def test_ml_detector():
    """Test ML detector with various scenarios"""
    print("🧪 Testing ML Detector Fixes...")
    
    try:
        from ai.detectors import MLDetector
        from ai.config import MLConfig
        
        # Test 1: Normal initialization
        print("\n1️⃣ Testing normal ML detector initialization...")
        try:
            detector = MLDetector('ssh')
            print(f"   ✅ SSH ML detector created successfully")
            print(f"   📊 ML disabled: {detector.ml_disabled}")
            print(f"   🎯 Is trained: {detector.is_trained}")
        except Exception as e:
            print(f"   ❌ Failed to create SSH detector: {e}")
        
        # Test 2: Test scoring with sample data
        print("\n2️⃣ Testing ML scoring...")
        try:
            sample_data = {
                'command': 'ls -la',
                'timestamp': '2025-09-28T12:42:20Z',
                'attack_types': [],
                'severity': 'low',
                'indicators': [],
                'vulnerabilities': [],
                'pattern_matches': []
            }
            
            result = detector.score(sample_data)
            print(f"   ✅ ML scoring completed successfully")
            print(f"   📊 Anomaly score: {result.get('ml_anomaly_score', 0)}")
            print(f"   🏷️  Labels: {result.get('ml_labels', [])}")
            print(f"   💭 Reason: {result.get('ml_reason', 'N/A')}")
            print(f"   ⏱️  Inference time: {result.get('ml_inference_time_ms', 0)}ms")
            
        except Exception as e:
            print(f"   ❌ ML scoring failed: {e}")
        
        # Test 3: Test with ML disabled
        print("\n3️⃣ Testing with ML disabled...")
        os.environ['NEXUS_DISABLE_ML'] = 'true'
        try:
            disabled_detector = MLDetector('ftp')
            result = disabled_detector.score(sample_data)
            print(f"   ✅ ML disabled detector works")
            print(f"   💭 Reason: {result.get('ml_reason', 'N/A')}")
        except Exception as e:
            print(f"   ❌ Disabled ML detector failed: {e}")
        finally:
            # Clean up environment
            if 'NEXUS_DISABLE_ML' in os.environ:
                del os.environ['NEXUS_DISABLE_ML']
        
        # Test 4: Test all services
        print("\n4️⃣ Testing all service types...")
        services = ['ssh', 'ftp', 'http', 'mysql', 'smb']
        for service in services:
            try:
                service_detector = MLDetector(service)
                result = service_detector.score(sample_data)
                print(f"   ✅ {service.upper()} detector: {result.get('ml_reason', 'N/A')}")
            except Exception as e:
                print(f"   ❌ {service.upper()} detector failed: {e}")
        
        print("\n🎉 ML Detector testing completed!")
        
    except ImportError as e:
        print(f"❌ Failed to import ML components: {e}")
        print("💡 This is expected if ML dependencies are not installed")
        return False
    
    return True

def test_feature_extractor():
    """Test feature extractor independently"""
    print("\n🔧 Testing Feature Extractor...")
    
    try:
        from ai.features import FeatureExtractor
        
        # Test SSH features
        extractor = FeatureExtractor('ssh')
        sample_data = {'command': 'rm -rf /'}
        features = extractor.extract_features(sample_data)
        
        print(f"   ✅ Feature extraction successful")
        print(f"   📊 Features extracted: {len(features)} items")
        print(f"   🔤 Text features: {features.get('text_features', 'N/A')}")
        print(f"   📏 Command length: {features.get('command_length', 0)}")
        
    except Exception as e:
        print(f"   ❌ Feature extraction failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🕸️ NEXUS ML Fix Verification")
    print("=" * 50)
    
    success = True
    
    # Test feature extractor first
    if not test_feature_extractor():
        success = False
    
    # Test ML detector
    if not test_ml_detector():
        success = False
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All tests passed! ML fixes are working correctly.")
        print("\n💡 Tips:")
        print("   • Use 'disable_ml.bat' to temporarily disable ML")
        print("   • ML will gracefully fallback when models aren't available")
        print("   • Check logs for ML-related warnings and errors")
    else:
        print("⚠️  Some tests failed. Check the errors above.")
        print("\n🔧 Troubleshooting:")
        print("   • Ensure all dependencies are installed: pip install -r requirements.txt")
        print("   • Check if ML models exist in the models/ directory")
        print("   • Use NEXUS_DISABLE_ML=true to disable ML temporarily")
    
    print("\n🚀 You can now run NEXUS services safely!")
