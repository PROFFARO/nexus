#!/usr/bin/env python3
"""
Working ML Test - Test ML integration with proper data format
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

def test_ssh_attack_analyzer():
    """Test SSH AttackAnalyzer with ML integration"""
    print("🔍 Testing SSH AttackAnalyzer with ML")
    
    try:
        # We need to mock the config first
        import configparser
        
        # Create a minimal config
        config = configparser.ConfigParser()
        config.add_section('ai_features')
        config.set('ai_features', 'attack_pattern_recognition', 'True')
        config.add_section('attack_detection')
        config.set('attack_detection', 'threat_scoring', 'True')
        config.set('attack_detection', 'alert_threshold', '70')
        config.set('attack_detection', 'sensitivity_level', 'medium')
        
        # Make config available globally (this is how the SSH server expects it)
        import sys
        sys.modules['__main__'].config = config
        
        # Now import the SSH server
        from ssh_server import AttackAnalyzer
        
        analyzer = AttackAnalyzer()
        
        if analyzer.ml_detector:
            print("✅ SSH ML detector initialized successfully")
            print(f"   Is Trained: {analyzer.ml_detector.is_trained}")
            
            # Test with a malicious command
            result = analyzer.analyze_command("rm -rf / --no-preserve-root")
            
            print(f"\n📊 SSH ML Analysis Results:")
            print(f"   Command: rm -rf / --no-preserve-root")
            print(f"   Severity: {result.get('severity', 'N/A')}")
            print(f"   Attack Types: {result.get('attack_types', [])}")
            print(f"   ML Anomaly Score: {result.get('ml_anomaly_score', 'N/A')}")
            print(f"   ML Labels: {result.get('ml_labels', 'N/A')}")
            print(f"   ML Confidence: {result.get('ml_confidence', 'N/A')}")
            print(f"   ML Reason: {result.get('ml_reason', 'N/A')}")
            
            # Test with a normal command
            result2 = analyzer.analyze_command("ls -la")
            
            print(f"\n📊 Normal Command Analysis:")
            print(f"   Command: ls -la")
            print(f"   Severity: {result2.get('severity', 'N/A')}")
            print(f"   Attack Types: {result2.get('attack_types', [])}")
            print(f"   ML Anomaly Score: {result2.get('ml_anomaly_score', 'N/A')}")
            print(f"   ML Labels: {result2.get('ml_labels', 'N/A')}")
            
            return True
        else:
            print("❌ SSH ML detector not initialized")
            return False
            
    except Exception as e:
        print(f"❌ SSH AttackAnalyzer test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_direct_feature_extraction():
    """Test direct feature extraction"""
    print("\n🔍 Testing Direct Feature Extraction")
    
    try:
        from ai.features import FeatureExtractor
        
        extractor = FeatureExtractor('ssh')
        
        # Test feature extraction
        test_data = {
            'command': 'rm -rf /',
            'timestamp': '2025-01-25T02:15:00Z',
            'severity': 'high'
        }
        
        features = extractor.extract_features(test_data)
        print(f"✅ Features extracted:")
        print(f"   Text Features: {features.get('text_features', 'N/A')[:50]}...")
        print(f"   Feature Keys: {list(features.keys())}")
        
        return True
        
    except Exception as e:
        print(f"❌ Feature extraction test failed: {e}")
        return False

def main():
    print("🚀 Working ML Integration Test")
    print("=" * 50)
    
    # Test feature extraction first
    test_direct_feature_extraction()
    
    # Test SSH analyzer
    test_ssh_attack_analyzer()

if __name__ == "__main__":
    main()
