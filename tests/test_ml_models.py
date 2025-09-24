#!/usr/bin/env python3
"""
NEXUS AI ML Model Testing Script
Test your trained ML models with sample data
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from ai.detectors import MLDetector
import json
from datetime import datetime

def test_service_ml(service_name, test_cases):
    """Test ML detection for a specific service"""
    print(f"\n🔍 Testing {service_name.upper()} ML Detection")
    print("=" * 50)
    
    try:
        detector = MLDetector(service_name)
        
        if not detector.is_trained:
            print(f"❌ {service_name} models not loaded!")
            return
        
        print(f"✅ {service_name} ML models loaded successfully")
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n📋 Test Case {i}: {test_case.get('description', 'Unknown')}")
            
            result = detector.score(test_case['data'])
            
            threat_level = "🔴 HIGH" if result['ml_anomaly_score'] > 0.7 else \
                          "🟡 MEDIUM" if result['ml_anomaly_score'] > 0.4 else "🟢 LOW"
            
            print(f"   Threat Level: {threat_level}")
            print(f"   Anomaly Score: {result['ml_anomaly_score']:.3f}")
            print(f"   Labels: {result['ml_labels']}")
            print(f"   Reason: {result['ml_reason']}")
            print(f"   Confidence: {result['ml_confidence']:.3f}")
            print(f"   Inference Time: {result['ml_inference_time_ms']}ms")
            
    except Exception as e:
        print(f"❌ Error testing {service_name}: {e}")

def main():
    print("🚀 NEXUS AI ML Model Testing")
    print("Testing all trained models with sample data...")
    
    # SSH Test Cases
    ssh_tests = [
        {
            'description': 'Malicious command - system destruction',
            'data': {
                'command': 'rm -rf /',
                'username': 'admin',
                'ip': '192.168.1.100',
                'timestamp': datetime.now().isoformat(),
                'session_duration': 30
            }
        },
        {
            'description': 'Normal command - directory listing',
            'data': {
                'command': 'ls -la',
                'username': 'user',
                'ip': '10.0.0.5',
                'timestamp': datetime.now().isoformat(),
                'session_duration': 120
            }
        },
        {
            'description': 'Suspicious command - network scanning',
            'data': {
                'command': 'nmap -sS 192.168.1.0/24',
                'username': 'hacker',
                'ip': '192.168.1.200',
                'timestamp': datetime.now().isoformat(),
                'session_duration': 5
            }
        }
    ]
    
    # HTTP Test Cases
    http_tests = [
        {
            'description': 'SQL Injection attempt',
            'data': {
                'method': 'GET',
                'url': '/login?user=admin&pass=\' OR 1=1--',
                'user_agent': 'sqlmap/1.0',
                'ip': '192.168.1.150',
                'timestamp': datetime.now().isoformat()
            }
        },
        {
            'description': 'Normal web request',
            'data': {
                'method': 'GET',
                'url': '/index.html',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'ip': '10.0.0.10',
                'timestamp': datetime.now().isoformat()
            }
        }
    ]
    
    # FTP Test Cases
    ftp_tests = [
        {
            'description': 'Brute force login attempt',
            'data': {
                'command': 'USER admin',
                'username': 'admin',
                'password': 'password123',
                'ip': '192.168.1.180',
                'timestamp': datetime.now().isoformat(),
                'failed_attempts': 50
            }
        },
        {
            'description': 'Normal FTP session',
            'data': {
                'command': 'LIST',
                'username': 'ftpuser',
                'ip': '10.0.0.20',
                'timestamp': datetime.now().isoformat(),
                'failed_attempts': 0
            }
        }
    ]
    
    # MySQL Test Cases
    mysql_tests = [
        {
            'description': 'Malicious SQL query',
            'data': {
                'query': 'SELECT * FROM users WHERE id=1; DROP TABLE users;--',
                'username': 'root',
                'database': 'production',
                'ip': '192.168.1.190',
                'timestamp': datetime.now().isoformat()
            }
        },
        {
            'description': 'Normal database query',
            'data': {
                'query': 'SELECT name, email FROM users WHERE active=1',
                'username': 'app_user',
                'database': 'app_db',
                'ip': '10.0.0.30',
                'timestamp': datetime.now().isoformat()
            }
        }
    ]
    
    # SMB Test Cases
    smb_tests = [
        {
            'description': 'Ransomware-like file access',
            'data': {
                'operation': 'WRITE',
                'filename': 'important_document.txt.encrypted',
                'username': 'admin',
                'ip': '192.168.1.220',
                'timestamp': datetime.now().isoformat(),
                'file_size': 1024000
            }
        },
        {
            'description': 'Normal file access',
            'data': {
                'operation': 'READ',
                'filename': 'report.pdf',
                'username': 'employee',
                'ip': '10.0.0.40',
                'timestamp': datetime.now().isoformat(),
                'file_size': 2048
            }
        }
    ]
    
    # Test all services
    test_service_ml('ssh', ssh_tests)
    test_service_ml('http', http_tests)
    test_service_ml('ftp', ftp_tests)
    test_service_ml('mysql', mysql_tests)
    test_service_ml('smb', smb_tests)
    
    print(f"\n🎉 ML Model Testing Complete!")
    print("Your trained models are ready for integration into the honeypot services.")

if __name__ == "__main__":
    main()
