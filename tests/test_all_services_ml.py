#!/usr/bin/env python3
"""
Test All Services ML Integration - Direct ML Testing
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

def test_ml_detectors_only():
    """Test ML detectors directly without service dependencies"""
    print("🔍 Testing All Service ML Detectors")
    
    services = ['ssh', 'http', 'ftp', 'mysql', 'smb']
    results = {}
    
    try:
        from ai.detectors import MLDetector
        
        for service in services:
            try:
                detector = MLDetector(service)
                is_trained = detector.is_trained
                results[service] = is_trained
                
                status = "✅ TRAINED" if is_trained else "❌ NOT TRAINED"
                print(f"   {service.upper()}: {status}")
                
                if is_trained:
                    # Quick test with minimal data
                    test_data = {
                        'command': 'test command' if service != 'http' else 'GET',
                        'query': 'SELECT * FROM test' if service == 'mysql' else 'test',
                        'timestamp': '2025-01-25T02:15:00Z'
                    }
                    result = detector.score(test_data)
                    score = result.get('ml_anomaly_score', 0)
                    print(f"      Sample Score: {score:.3f}")
                
            except Exception as e:
                print(f"   {service.upper()}: ❌ ERROR - {e}")
                results[service] = False
        
        return results
        
    except Exception as e:
        print(f"❌ ML Detector testing failed: {e}")
        return {}

def test_service_analyzers():
    """Test service analyzers with ML integration"""
    print("\n🔍 Testing Service Analyzers ML Integration")
    
    integration_status = {}
    
    # Test SMB Integration (NEWLY UPDATED)
    print("   Testing SMB Service...")
    try:
        from service_emulators.SMB.smb_server import AttackAnalyzer as SMBAnalyzer
        smb_analyzer = SMBAnalyzer()
        
        if hasattr(smb_analyzer, 'ml_detector') and smb_analyzer.ml_detector:
            print("      ✅ ML Detector initialized")
            
            # Test with a malicious SMB command
            test_result = smb_analyzer.analyze_command("net user administrator password123 /add")
            
            # Check for comprehensive ML fields
            ml_fields = ['ml_anomaly_score', 'ml_labels', 'ml_confidence', 'ml_reason', 'ml_inference_time_ms']
            has_comprehensive = all(key in test_result for key in ml_fields)
            
            if has_comprehensive:
                integration_status['smb'] = 'Phase 5 Complete'
                print("      ✅ Phase 5 Complete ML Integration")
                print(f"         ML Anomaly Score: {test_result.get('ml_anomaly_score', 0):.3f}")
                print(f"         ML Labels: {test_result.get('ml_labels', [])}")
                print(f"         ML Confidence: {test_result.get('ml_confidence', 0):.3f}")
                print(f"         ML Reason: {test_result.get('ml_reason', 'N/A')}")
                print(f"         Inference Time: {test_result.get('ml_inference_time_ms', 0):.1f}ms")
            else:
                integration_status['smb'] = 'Basic Integration'
                print("      ⚠️ Basic Integration Only")
                print(f"         Missing fields: {[f for f in ml_fields if f not in test_result]}")
        else:
            integration_status['smb'] = 'No ML Integration'
            print("      ❌ No ML Detector found")
            
    except Exception as e:
        integration_status['smb'] = f'Error: {str(e)[:50]}'
        print(f"      ❌ Error: {e}")
    
    # Test HTTP Integration
    print("   Testing HTTP Service...")
    try:
        from service_emulators.HTTP.http_server import AttackAnalyzer as HTTPAnalyzer
        http_analyzer = HTTPAnalyzer()
        
        if hasattr(http_analyzer, 'ml_detector') and http_analyzer.ml_detector:
            print("      ✅ ML Detector initialized")
            
            test_result = http_analyzer.analyze_request("GET", "/admin", {}, "")
            ml_fields = ['ml_anomaly_score', 'ml_labels', 'ml_confidence', 'ml_reason']
            has_comprehensive = all(key in test_result for key in ml_fields)
            
            integration_status['http'] = 'Phase 5 Complete' if has_comprehensive else 'Basic Integration'
            print(f"      ✅ {integration_status['http']}")
            if has_comprehensive:
                print(f"         ML Anomaly Score: {test_result.get('ml_anomaly_score', 0):.3f}")
        else:
            integration_status['http'] = 'No ML Integration'
            print("      ❌ No ML Detector found")
            
    except Exception as e:
        integration_status['http'] = f'Error: {str(e)[:50]}'
        print(f"      ❌ Error: {e}")
    
    # Test FTP Integration
    print("   Testing FTP Service...")
    try:
        from service_emulators.FTP.ftp_server import AttackAnalyzer as FTPAnalyzer
        ftp_analyzer = FTPAnalyzer()
        
        if hasattr(ftp_analyzer, 'ml_detector') and ftp_analyzer.ml_detector:
            print("      ✅ ML Detector initialized")
            
            test_result = ftp_analyzer.analyze_command("DELE /etc/passwd")
            ml_fields = ['ml_anomaly_score', 'ml_labels', 'ml_confidence', 'ml_reason']
            has_comprehensive = all(key in test_result for key in ml_fields)
            
            integration_status['ftp'] = 'Phase 5 Complete' if has_comprehensive else 'Basic Integration'
            print(f"      ✅ {integration_status['ftp']}")
            if has_comprehensive:
                print(f"         ML Anomaly Score: {test_result.get('ml_anomaly_score', 0):.3f}")
        else:
            integration_status['ftp'] = 'No ML Integration'
            print("      ❌ No ML Detector found")
            
    except Exception as e:
        integration_status['ftp'] = f'Error: {str(e)[:50]}'
        print(f"      ❌ Error: {e}")
    
    # Test MySQL Integration
    print("   Testing MySQL Service...")
    try:
        from service_emulators.MySQL.mysql_server import AttackAnalyzer as MySQLAnalyzer
        mysql_analyzer = MySQLAnalyzer()
        
        if hasattr(mysql_analyzer, 'ml_detector') and mysql_analyzer.ml_detector:
            print("      ✅ ML Detector initialized")
            
            test_result = mysql_analyzer.analyze_query("SELECT * FROM users WHERE 1=1; DROP TABLE users;")
            ml_fields = ['ml_anomaly_score', 'ml_labels', 'ml_confidence', 'ml_reason']
            has_comprehensive = all(key in test_result for key in ml_fields)
            
            integration_status['mysql'] = 'Phase 5 Complete' if has_comprehensive else 'Basic Integration'
            print(f"      ✅ {integration_status['mysql']}")
            if has_comprehensive:
                print(f"         ML Anomaly Score: {test_result.get('ml_anomaly_score', 0):.3f}")
        else:
            integration_status['mysql'] = 'No ML Integration'
            print("      ❌ No ML Detector found")
            
    except Exception as e:
        integration_status['mysql'] = f'Error: {str(e)[:50]}'
        print(f"      ❌ Error: {e}")
    
    return integration_status

def main():
    print("🚀 COMPREHENSIVE ML INTEGRATION TEST")
    print("Testing all services ML integration...")
    print("=" * 60)
    
    # Test ML detectors
    detector_results = test_ml_detectors_only()
    
    # Test service analyzers
    analyzer_results = test_service_analyzers()
    
    # Summary
    print("\n📊 FINAL SUMMARY")
    print("=" * 60)
    
    total_services = 5
    trained_detectors = sum(1 for trained in detector_results.values() if trained)
    phase5_services = sum(1 for status in analyzer_results.values() if 'Phase 5 Complete' in status)
    
    print(f"   Services with Trained ML Models: {trained_detectors}/{total_services}")
    print(f"   Services with Phase 5 Integration: {phase5_services}/{total_services}")
    print(f"   Training Success Rate: {(trained_detectors/total_services)*100:.1f}%")
    print(f"   Integration Completion Rate: {(phase5_services/total_services)*100:.1f}%")
    
    print(f"\n🎯 INTEGRATION STATUS:")
    
    if phase5_services == total_services:
        print("   🎉 FULLY INTEGRATED - All services have Phase 5 Complete ML integration!")
        print("   ✅ Real-time ML threat detection is operational across all services")
        print("   ✅ SMB service successfully upgraded to Phase 5!")
    elif phase5_services >= 4:
        print("   ⚠️ NEARLY COMPLETE - Most services have comprehensive ML integration")
        print("   🔧 One service may need Phase 5 upgrade")
    elif phase5_services >= 3:
        print("   ⚠️ MOSTLY INTEGRATED - Most services have comprehensive ML integration")
        print("   🔧 Some services need Phase 5 ML integration upgrade")
    else:
        print("   ❌ NEEDS WORK - Integration incomplete")
        print("   🔧 Significant fixes required")
    
    # Save detailed report
    import json
    report = {
        'timestamp': '2025-01-25T03:00:00Z',
        'detector_results': detector_results,
        'analyzer_results': analyzer_results,
        'phase5_completion_rate': f"{(phase5_services/total_services)*100:.1f}%",
        'overall_status': 'FULLY_INTEGRATED' if phase5_services == total_services else 'MOSTLY_INTEGRATED' if phase5_services >= 3 else 'NEEDS_WORK'
    }
    
    with open('comprehensive_ml_integration_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Detailed report saved: comprehensive_ml_integration_report.json")
    
    return report

if __name__ == "__main__":
    main()
