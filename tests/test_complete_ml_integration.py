#!/usr/bin/env python3
"""
NEXUS AI - Complete ML Integration Test Suite
Tests ML integration across all services after fixes are applied
"""

import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def test_ssh_ml_integration():
    """Test SSH ML integration"""
    print("\n🔍 Testing SSH ML Integration")
    print("=" * 50)
    
    try:
        from service_emulators.SSH.ssh_server import AttackAnalyzer
        
        analyzer = AttackAnalyzer()
        
        if not analyzer.ml_detector:
            print("❌ SSH ML detector not initialized")
            return False
        
        # Test malicious command
        result = analyzer.analyze_command("rm -rf / --no-preserve-root")
        
        print(f"✅ SSH ML Analysis Results:")
        print(f"   Command: rm -rf / --no-preserve-root")
        print(f"   ML Anomaly Score: {result.get('ml_anomaly_score', 'N/A')}")
        print(f"   ML Labels: {result.get('ml_labels', 'N/A')}")
        print(f"   ML Confidence: {result.get('ml_confidence', 'N/A')}")
        print(f"   Severity: {result.get('severity', 'N/A')}")
        print(f"   Attack Types: {result.get('attack_types', 'N/A')}")
        
        return 'ml_anomaly_score' in result
        
    except Exception as e:
        print(f"❌ SSH ML test failed: {e}")
        return False

def test_http_ml_integration():
    """Test HTTP ML integration"""
    print("\n🔍 Testing HTTP ML Integration")
    print("=" * 50)
    
    try:
        from service_emulators.HTTP.http_server import AttackAnalyzer
        
        analyzer = AttackAnalyzer()
        
        if not analyzer.ml_detector:
            print("❌ HTTP ML detector not initialized")
            return False
        
        # Test SQL injection request
        result = analyzer.analyze_request(
            method="GET",
            path="/login?user=admin&pass=' OR 1=1--",
            headers={"User-Agent": "sqlmap/1.0"},
            body=""
        )
        
        print(f"✅ HTTP ML Analysis Results:")
        print(f"   Request: GET /login?user=admin&pass=' OR 1=1--")
        print(f"   ML Anomaly Score: {result.get('ml_anomaly_score', 'N/A')}")
        print(f"   ML Labels: {result.get('ml_labels', 'N/A')}")
        print(f"   ML Confidence: {result.get('ml_confidence', 'N/A')}")
        print(f"   Severity: {result.get('severity', 'N/A')}")
        print(f"   Attack Types: {result.get('attack_types', 'N/A')}")
        
        return 'ml_anomaly_score' in result
        
    except Exception as e:
        print(f"❌ HTTP ML test failed: {e}")
        return False

def test_ftp_ml_integration():
    """Test FTP ML integration"""
    print("\n🔍 Testing FTP ML Integration")
    print("=" * 50)
    
    try:
        from service_emulators.FTP.ftp_server import AttackAnalyzer
        
        analyzer = AttackAnalyzer()
        
        if not analyzer.ml_detector:
            print("❌ FTP ML detector not initialized")
            return False
        
        # Test if analyze_command method exists (needs to be added)
        if not hasattr(analyzer, 'analyze_command'):
            print("⚠️ FTP analyze_command method not implemented yet")
            print("   This needs to be added per ml_integration_fixes.py")
            return False
        
        result = analyzer.analyze_command("USER admin", "admin", "192.168.1.100")
        
        print(f"✅ FTP ML Analysis Results:")
        print(f"   Command: USER admin")
        print(f"   ML Anomaly Score: {result.get('ml_anomaly_score', 'N/A')}")
        print(f"   ML Labels: {result.get('ml_labels', 'N/A')}")
        
        return 'ml_anomaly_score' in result
        
    except Exception as e:
        print(f"❌ FTP ML test failed: {e}")
        return False

def test_mysql_ml_integration():
    """Test MySQL ML integration"""
    print("\n🔍 Testing MySQL ML Integration")
    print("=" * 50)
    
    try:
        from service_emulators.MySQL.mysql_server import AttackAnalyzer
        
        analyzer = AttackAnalyzer()
        
        if not analyzer.ml_detector:
            print("❌ MySQL ML detector not initialized")
            return False
        
        # Test if analyze_query method exists (needs to be added)
        if not hasattr(analyzer, 'analyze_query'):
            print("⚠️ MySQL analyze_query method not implemented yet")
            print("   This needs to be added per ml_integration_fixes.py")
            return False
        
        result = analyzer.analyze_query(
            "SELECT * FROM users WHERE id=1; DROP TABLE users;--",
            "root",
            "production"
        )
        
        print(f"✅ MySQL ML Analysis Results:")
        print(f"   Query: SELECT * FROM users WHERE id=1; DROP TABLE users;--")
        print(f"   ML Anomaly Score: {result.get('ml_anomaly_score', 'N/A')}")
        print(f"   ML Labels: {result.get('ml_labels', 'N/A')}")
        
        return 'ml_anomaly_score' in result
        
    except Exception as e:
        print(f"❌ MySQL ML test failed: {e}")
        return False

def test_smb_ml_integration():
    """Test SMB ML integration"""
    print("\n🔍 Testing SMB ML Integration")
    print("=" * 50)
    
    try:
        from service_emulators.SMB.smb_server import AttackAnalyzer
        
        analyzer = AttackAnalyzer()
        
        if not analyzer.ml_detector:
            print("❌ SMB ML detector not initialized")
            return False
        
        # Test if analyze_operation method exists (needs to be added)
        if not hasattr(analyzer, 'analyze_operation'):
            print("⚠️ SMB analyze_operation method not implemented yet")
            print("   This needs to be added per ml_integration_fixes.py")
            return False
        
        result = analyzer.analyze_operation(
            "WRITE",
            "important_document.txt.encrypted",
            "admin"
        )
        
        print(f"✅ SMB ML Analysis Results:")
        print(f"   Operation: WRITE important_document.txt.encrypted")
        print(f"   ML Anomaly Score: {result.get('ml_anomaly_score', 'N/A')}")
        print(f"   ML Labels: {result.get('ml_labels', 'N/A')}")
        
        return 'ml_anomaly_score' in result
        
    except Exception as e:
        print(f"❌ SMB ML test failed: {e}")
        return False

def test_ml_models_availability():
    """Test that all ML models are available"""
    print("\n🔍 Testing ML Models Availability")
    print("=" * 50)
    
    models_dir = Path("models")
    services = ["ssh", "http", "ftp", "mysql", "smb"]
    
    all_available = True
    
    for service in services:
        service_dir = models_dir / service
        if not service_dir.exists():
            print(f"❌ {service.upper()} models directory missing")
            all_available = False
            continue
        
        required_files = [
            "isolation_forest_anomaly.pkl",
            "one_class_svm_anomaly.pkl", 
            "hdbscan_clustering.pkl",
            "supervised_classifier.pkl",
            "embeddings.cache",
            "faiss.index",
            "scaler.pkl",
            "vectorizer.pkl",
            "label_encoder.pkl"
        ]
        
        missing_files = []
        for file in required_files:
            if not (service_dir / file).exists():
                missing_files.append(file)
        
        if missing_files:
            print(f"❌ {service.upper()} missing files: {missing_files}")
            all_available = False
        else:
            print(f"✅ {service.upper()} all models available")
    
    return all_available

def test_direct_ml_detector():
    """Test MLDetector directly"""
    print("\n🔍 Testing MLDetector Direct Usage")
    print("=" * 50)
    
    try:
        from ai.detectors import MLDetector
        
        # Test each service
        services = ["ssh", "http", "ftp", "mysql", "smb"]
        results = {}
        
        for service in services:
            try:
                detector = MLDetector(service)
                
                if not detector.is_trained:
                    print(f"❌ {service.upper()} detector not trained")
                    results[service] = False
                    continue
                
                # Test with sample data
                test_data = {
                    'command': 'rm -rf /',
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'high'
                }
                
                result = detector.score(test_data)
                
                print(f"✅ {service.upper()} detector working:")
                print(f"   Anomaly Score: {result.get('ml_anomaly_score', 0):.3f}")
                print(f"   Labels: {result.get('ml_labels', [])}")
                print(f"   Inference Time: {result.get('ml_inference_time_ms', 0)}ms")
                
                results[service] = True
                
            except Exception as e:
                print(f"❌ {service.upper()} detector failed: {e}")
                results[service] = False
        
        return all(results.values())
        
    except Exception as e:
        print(f"❌ MLDetector import failed: {e}")
        return False

def generate_integration_report():
    """Generate comprehensive integration report"""
    print("\n📊 COMPREHENSIVE ML INTEGRATION REPORT")
    print("=" * 60)
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'tests': {}
    }
    
    # Run all tests
    results['tests']['ml_models_available'] = test_ml_models_availability()
    results['tests']['direct_ml_detector'] = test_direct_ml_detector()
    results['tests']['ssh_integration'] = test_ssh_ml_integration()
    results['tests']['http_integration'] = test_http_ml_integration()
    results['tests']['ftp_integration'] = test_ftp_ml_integration()
    results['tests']['mysql_integration'] = test_mysql_ml_integration()
    results['tests']['smb_integration'] = test_smb_ml_integration()
    
    # Calculate overall status
    total_tests = len(results['tests'])
    passed_tests = sum(1 for result in results['tests'].values() if result)
    
    print(f"\n🎯 OVERALL RESULTS:")
    print(f"   Tests Passed: {passed_tests}/{total_tests}")
    print(f"   Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if passed_tests == total_tests:
        print("   Status: ✅ FULLY INTEGRATED")
    elif passed_tests >= total_tests * 0.6:
        print("   Status: ⚠️ PARTIALLY INTEGRATED")
    else:
        print("   Status: ❌ NEEDS WORK")
    
    # Save report
    with open('ml_integration_test_report.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📄 Report saved: ml_integration_test_report.json")
    
    return results

def main():
    """Main test function"""
    print("🚀 NEXUS AI - Complete ML Integration Test Suite")
    print("Testing ML integration across all services...")
    
    # Generate comprehensive report
    report = generate_integration_report()
    
    # Provide recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    
    if not report['tests']['ml_models_available']:
        print("   1. ⚠️ Ensure all ML models are trained and saved")
        print("      Run: python train_models.py --services all --algorithms all")
    
    if not report['tests']['direct_ml_detector']:
        print("   2. ⚠️ Fix MLDetector issues")
        print("      Check ai/detectors.py and model file paths")
    
    if not report['tests']['ssh_integration']:
        print("   3. ⚠️ SSH integration needs fixing")
    
    if not report['tests']['http_integration']:
        print("   4. ⚠️ Apply HTTP ML fixes from ml_integration_fixes.py")
    
    if not report['tests']['ftp_integration']:
        print("   5. ⚠️ Add FTP ML integration code")
    
    if not report['tests']['mysql_integration']:
        print("   6. ⚠️ Add MySQL ML integration code")
    
    if not report['tests']['smb_integration']:
        print("   7. ⚠️ Add SMB ML integration code")
    
    print(f"\n✨ Next Steps:")
    print("   1. Apply fixes from ml_integration_fixes.py")
    print("   2. Re-run this test to verify integration")
    print("   3. Test with live honeypot sessions")

if __name__ == "__main__":
    main()
