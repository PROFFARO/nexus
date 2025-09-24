#!/usr/bin/env python3
"""
NEXUS AI - Complete ML Integration Fixes
This file contains all the code changes needed to fully integrate ML across all services
"""

# =============================================================================
# HTTP SERVICE ML INTEGRATION FIX
# =============================================================================

# Replace the ml_data section in HTTP/http_server.py around line 187-196:
HTTP_ML_DATA_FIX = '''
                # Prepare comprehensive ML data
                ml_data = {
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
                
                logging.info(f"HTTP ML Analysis: Score={ml_score:.3f}, Labels={ml_results.get('ml_labels', [])}, Confidence={ml_results.get('ml_confidence', 0):.3f}")
'''

# =============================================================================
# FTP SERVICE ML INTEGRATION
# =============================================================================

FTP_ML_INTEGRATION = '''
# Add this to FTP/ftp_server.py after the AttackAnalyzer.__init__ method:

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
        
        # Pattern-based analysis (existing logic)
        # ... existing pattern matching code ...
        
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

# =============================================================================
# MYSQL SERVICE ML INTEGRATION
# =============================================================================

MYSQL_ML_INTEGRATION = '''
# Add this to MySQL/mysql_server.py for query analysis:

    def analyze_query(self, query: str, username: str = "", database: str = "") -> Dict[str, Any]:
        """Analyze MySQL query for attack patterns with ML integration"""
        analysis = {
            'query': query,
            'username': username,
            'database': database,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'attack_types': [],
            'severity': 'low',
            'indicators': [],
            'vulnerabilities': [],
            'pattern_matches': []
        }
        
        # Pattern-based analysis for SQL injection, etc.
        # ... existing pattern matching code ...
        
        # Add ML-based analysis if available
        if self.ml_detector:
            try:
                ml_data = {
                    'query': query,
                    'username': username,
                    'database': database,
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
                
                logging.info(f"MySQL ML Analysis: Score={ml_score:.3f}, Labels={ml_results.get('ml_labels', [])}")
                        
            except Exception as e:
                logging.error(f"MySQL ML analysis failed: {e}")
                analysis['ml_error'] = str(e)
                analysis['ml_anomaly_score'] = 0.0
                analysis['ml_labels'] = ['ml_error']
        
        return analysis
'''

# =============================================================================
# SMB SERVICE ML INTEGRATION
# =============================================================================

SMB_ML_INTEGRATION = '''
# Add this to SMB/smb_server.py for file operation analysis:

    def analyze_operation(self, operation: str, filename: str = "", username: str = "") -> Dict[str, Any]:
        """Analyze SMB operation for attack patterns with ML integration"""
        analysis = {
            'operation': operation,
            'filename': filename,
            'username': username,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'attack_types': [],
            'severity': 'low',
            'indicators': [],
            'vulnerabilities': [],
            'pattern_matches': []
        }
        
        # Pattern-based analysis for ransomware, etc.
        # ... existing pattern matching code ...
        
        # Add ML-based analysis if available
        if self.ml_detector:
            try:
                ml_data = {
                    'operation': operation,
                    'filename': filename,
                    'username': username,
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
                
                logging.info(f"SMB ML Analysis: Score={ml_score:.3f}, Labels={ml_results.get('ml_labels', [])}")
                        
            except Exception as e:
                logging.error(f"SMB ML analysis failed: {e}")
                analysis['ml_error'] = str(e)
                analysis['ml_anomaly_score'] = 0.0
                analysis['ml_labels'] = ['ml_error']
        
        return analysis
'''

# =============================================================================
# REPORT GENERATOR ML ENHANCEMENT
# =============================================================================

REPORT_ML_ENHANCEMENT = '''
# Add this to all report_generator.py files to include ML insights:

    def _analyze_ml_insights(self, sessions: List[Dict]) -> Dict[str, Any]:
        """Analyze ML insights from session data"""
        ml_insights = {
            'total_ml_detections': 0,
            'high_confidence_detections': 0,
            'ml_anomaly_distribution': {},
            'ml_cluster_analysis': {},
            'avg_inference_time': 0,
            'ml_enhanced_threats': []
        }
        
        inference_times = []
        anomaly_scores = []
        
        for session in sessions:
            for item in session.get('commands', session.get('requests', session.get('queries', []))):
                # Check for ML results in the item
                if 'ml_anomaly_score' in item:
                    ml_insights['total_ml_detections'] += 1
                    
                    ml_score = item.get('ml_anomaly_score', 0)
                    ml_confidence = item.get('ml_confidence', 0)
                    ml_labels = item.get('ml_labels', [])
                    
                    anomaly_scores.append(ml_score)
                    
                    if ml_confidence > 0.8:
                        ml_insights['high_confidence_detections'] += 1
                    
                    # Track ML labels
                    for label in ml_labels:
                        if label not in ml_insights['ml_anomaly_distribution']:
                            ml_insights['ml_anomaly_distribution'][label] = 0
                        ml_insights['ml_anomaly_distribution'][label] += 1
                    
                    # Track inference times
                    inference_time = item.get('ml_inference_time_ms', 0)
                    if inference_time > 0:
                        inference_times.append(inference_time)
                    
                    # Collect high-threat ML detections
                    if ml_score > 0.7:
                        ml_insights['ml_enhanced_threats'].append({
                            'session_id': session.get('session_id', 'unknown'),
                            'timestamp': item.get('timestamp', ''),
                            'ml_score': ml_score,
                            'ml_confidence': ml_confidence,
                            'ml_reason': item.get('ml_reason', ''),
                            'command': item.get('command', item.get('query', item.get('operation', '')))
                        })
        
        # Calculate averages
        if inference_times:
            ml_insights['avg_inference_time'] = sum(inference_times) / len(inference_times)
        
        if anomaly_scores:
            ml_insights['avg_anomaly_score'] = sum(anomaly_scores) / len(anomaly_scores)
            ml_insights['max_anomaly_score'] = max(anomaly_scores)
        
        return ml_insights
'''

print("✅ ML Integration fixes generated successfully!")
print("📁 File saved: ml_integration_fixes.py")
print("\n🔧 Next Steps:")
print("1. Apply the HTTP service fix manually")
print("2. Add FTP/MySQL/SMB ML integration code")
print("3. Enhance report generators with ML insights")
print("4. Test the complete ML integration")
