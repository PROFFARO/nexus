#!/usr/bin/env python3
"""
NEXUS AI - Automatic ML Integration Fix Applier
Automatically applies ML integration fixes to all service files
"""

import os
import shutil
from pathlib import Path
import re

def backup_files():
    """Create backups of original files"""
    print("📦 Creating backups of original files...")
    
    files_to_backup = [
        "src/service_emulators/HTTP/http_server.py",
        "src/service_emulators/FTP/ftp_server.py", 
        "src/service_emulators/MySQL/mysql_server.py",
        "src/service_emulators/SMB/smb_server.py"
    ]
    
    backup_dir = Path("backups")
    backup_dir.mkdir(exist_ok=True)
    
    for file_path in files_to_backup:
        if Path(file_path).exists():
            backup_path = backup_dir / Path(file_path).name
            shutil.copy2(file_path, backup_path)
            print(f"   ✅ Backed up {file_path} to {backup_path}")

def apply_http_ml_fix():
    """Apply ML integration fix to HTTP server"""
    print("\n🔧 Applying HTTP ML Integration Fix...")
    
    file_path = Path("src/service_emulators/HTTP/http_server.py")
    
    if not file_path.exists():
        print(f"   ❌ File not found: {file_path}")
        return False
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find and replace the ML data section
        old_pattern = r"ml_data = \{\s*'request': request_data,.*?\}"
        
        new_ml_data = """ml_data = {
                    'method': method,
                    'url': path,
                    'headers': str(headers),
                    'body': body,
                    'timestamp': analysis['timestamp'],
                    'attack_types': analysis['attack_types'],
                    'severity': analysis['severity'],
                    'indicators': analysis['indicators'],
                    'vulnerabilities': analysis['vulnerabilities'],
                    'pattern_matches': analysis['pattern_matches']
                }
                
                # Get ML scoring results
                ml_results = self.ml_detector.score(ml_data)
                
                # Integrate ML results into analysis
                analysis['ml_anomaly_score'] = ml_results.get('ml_anomaly_score', 0.0)
                analysis['ml_labels'] = ml_results.get('ml_labels', [])
                analysis['ml_cluster'] = ml_results.get('ml_cluster', -1)
                analysis['ml_reason'] = ml_results.get('ml_reason', 'No ML analysis')
                analysis['ml_confidence'] = ml_results.get('ml_confidence', 0.0)
                analysis['ml_inference_time_ms'] = ml_results.get('ml_inference_time_ms', 0)
                
                # Enhance severity based on ML anomaly score
                ml_score = ml_results.get('ml_anomaly_score', 0)
                if ml_score > 0.8:
                    if analysis['severity'] in ['low', 'medium']:
                        analysis['severity'] = 'high'
                        analysis['attack_types'].append('ml_anomaly_high')
                elif ml_score > 0.6:
                    if analysis['severity'] == 'low':
                        analysis['severity'] = 'medium'
                        analysis['attack_types'].append('ml_anomaly_medium')
                
                # Add ML-specific indicators
                if 'anomaly' in ml_results.get('ml_labels', []):
                    analysis['indicators'].append(f"ML Anomaly Detection: {ml_results.get('ml_reason', 'Unknown')}")
                
                logging.info(f"HTTP ML Analysis: Score={ml_score:.3f}, Labels={ml_results.get('ml_labels', [])}, Confidence={ml_results.get('ml_confidence', 0):.3f}")"""
        
        # Replace the old ML section
        if "ml_data = {" in content:
            # Find the start and end of the ml_data block
            start_idx = content.find("ml_data = {")
            if start_idx != -1:
                # Find the end of the ml_data assignment and subsequent ML processing
                brace_count = 0
                end_idx = start_idx
                in_ml_data = False
                
                for i, char in enumerate(content[start_idx:], start_idx):
                    if char == '{':
                        brace_count += 1
                        in_ml_data = True
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0 and in_ml_data:
                            # Found end of ml_data dict, now find end of ML processing
                            remaining = content[i+1:]
                            # Look for the next major section or exception handling
                            except_match = re.search(r'\n\s+except Exception as e:', remaining)
                            if except_match:
                                end_idx = i + 1 + except_match.start()
                                break
                            else:
                                end_idx = i + 1
                                break
                
                if end_idx > start_idx:
                    # Replace the ML section
                    new_content = content[:start_idx] + new_ml_data + content[end_idx:]
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    print(f"   ✅ HTTP ML integration fix applied successfully")
                    return True
        
        print(f"   ⚠️ Could not find ML section to replace in HTTP server")
        return False
        
    except Exception as e:
        print(f"   ❌ Error applying HTTP fix: {e}")
        return False

def add_ftp_ml_integration():
    """Add ML integration to FTP server"""
    print("\n🔧 Adding FTP ML Integration...")
    
    file_path = Path("src/service_emulators/FTP/ftp_server.py")
    
    if not file_path.exists():
        print(f"   ❌ File not found: {file_path}")
        return False
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if analyze_command method already exists
        if "def analyze_command(" in content:
            print(f"   ⚠️ FTP analyze_command method already exists")
            return True
        
        # Find the AttackAnalyzer class and add the method
        class_match = re.search(r'class AttackAnalyzer:.*?\n(.*?)(?=\nclass|\nif __name__|\Z)', content, re.DOTALL)
        
        if class_match:
            analyze_command_method = '''
    def analyze_command(self, command: str, username: str = "", client_ip: str = "") -> Dict[str, Any]:
        """Analyze FTP command for attack patterns with ML integration"""
        analysis = {
            'command': command,
            'username': username,
            'client_ip': client_ip,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'attack_types': [],
            'severity': 'low',
            'indicators': [],
            'vulnerabilities': [],
            'pattern_matches': []
        }
        
        # Add existing pattern-based analysis here if needed
        
        # Add ML-based analysis if available
        if self.ml_detector:
            try:
                ml_data = {
                    'command': command,
                    'username': username,
                    'client_ip': client_ip,
                    'timestamp': analysis['timestamp'],
                    'attack_types': analysis['attack_types'],
                    'severity': analysis['severity']
                }
                
                ml_results = self.ml_detector.score(ml_data)
                
                # Integrate ML results
                analysis['ml_anomaly_score'] = ml_results.get('ml_anomaly_score', 0.0)
                analysis['ml_labels'] = ml_results.get('ml_labels', [])
                analysis['ml_cluster'] = ml_results.get('ml_cluster', -1)
                analysis['ml_reason'] = ml_results.get('ml_reason', 'No ML analysis')
                analysis['ml_confidence'] = ml_results.get('ml_confidence', 0.0)
                
                # Enhance severity based on ML
                ml_score = ml_results.get('ml_anomaly_score', 0)
                if ml_score > 0.8:
                    if analysis['severity'] in ['low', 'medium']:
                        analysis['severity'] = 'high'
                        analysis['attack_types'].append('ml_anomaly_high')
                elif ml_score > 0.6:
                    if analysis['severity'] == 'low':
                        analysis['severity'] = 'medium'
                        analysis['attack_types'].append('ml_anomaly_medium')
                
                logging.info(f"FTP ML Analysis: Score={ml_score:.3f}, Labels={ml_results.get('ml_labels', [])}")
                        
            except Exception as e:
                logging.error(f"FTP ML analysis failed: {e}")
                analysis['ml_error'] = str(e)
                analysis['ml_anomaly_score'] = 0.0
                analysis['ml_labels'] = ['ml_error']
        
        return analysis
'''
            
            # Find a good place to insert the method (after __init__ method)
            init_end = content.find("def __init__(", content.find("class AttackAnalyzer:"))
            if init_end != -1:
                # Find the end of __init__ method
                method_end = content.find("\n    def ", init_end + 1)
                if method_end == -1:
                    method_end = content.find("\nclass ", init_end + 1)
                if method_end == -1:
                    method_end = len(content)
                
                # Insert the new method
                new_content = content[:method_end] + analyze_command_method + content[method_end:]
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                print(f"   ✅ FTP ML integration added successfully")
                return True
        
        print(f"   ⚠️ Could not find suitable location to add FTP ML integration")
        return False
        
    except Exception as e:
        print(f"   ❌ Error adding FTP ML integration: {e}")
        return False

def create_integration_summary():
    """Create a summary of integration status"""
    print("\n📊 Creating Integration Summary...")
    
    summary = {
        "timestamp": "2025-01-25T02:15:00Z",
        "integration_status": {
            "ssh": "✅ FULLY INTEGRATED (Enhanced ML scoring)",
            "http": "⚠️ NEEDS MANUAL FIX (Use ml_integration_fixes.py)",
            "ftp": "⚠️ PARTIAL (ML detector initialized, needs analyze_command)",
            "mysql": "⚠️ PARTIAL (ML detector initialized, needs analyze_query)",
            "smb": "⚠️ PARTIAL (ML detector initialized, needs analyze_operation)"
        },
        "next_steps": [
            "1. Apply HTTP ML fixes manually from ml_integration_fixes.py",
            "2. Add FTP analyze_command method",
            "3. Add MySQL analyze_query method", 
            "4. Add SMB analyze_operation method",
            "5. Test with test_complete_ml_integration.py",
            "6. Verify real-time detection in live sessions"
        ],
        "files_created": [
            "ml_integration_fixes.py - Complete fix code",
            "test_complete_ml_integration.py - Test suite",
            "apply_ml_fixes.py - Auto-fix script",
            "test_ml_models.py - Model testing script"
        ]
    }
    
    with open("ml_integration_summary.json", "w") as f:
        import json
        json.dump(summary, f, indent=2)
    
    print("   ✅ Summary saved to ml_integration_summary.json")
    
    return summary

def main():
    """Main function to apply all ML fixes"""
    print("🚀 NEXUS AI - Automatic ML Integration Fix Applier")
    print("=" * 60)
    
    # Create backups
    backup_files()
    
    # Apply fixes
    results = {}
    results['http'] = apply_http_ml_fix()
    results['ftp'] = add_ftp_ml_integration()
    
    # Create summary
    summary = create_integration_summary()
    
    print(f"\n🎯 FIX APPLICATION RESULTS:")
    for service, success in results.items():
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"   {service.upper()}: {status}")
    
    print(f"\n💡 MANUAL STEPS REQUIRED:")
    print("   1. Review and apply remaining fixes from ml_integration_fixes.py")
    print("   2. Add MySQL and SMB analyze methods")
    print("   3. Test integration with test_complete_ml_integration.py")
    print("   4. Run live honeypot tests")
    
    print(f"\n📁 FILES CREATED:")
    print("   - ml_integration_fixes.py (Complete fix code)")
    print("   - test_complete_ml_integration.py (Test suite)")
    print("   - ml_integration_summary.json (Status summary)")
    print("   - backups/ (Original file backups)")

if __name__ == "__main__":
    main()
