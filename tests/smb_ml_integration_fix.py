#!/usr/bin/env python3
"""
SMB ML Integration Fix - Complete Phase 5 Integration
Replace the ML section in SMB/smb_server.py with this comprehensive implementation
"""

# =============================================================================
# EXACT CODE TO REPLACE IN SMB/smb_server.py
# =============================================================================

# FIND THIS SECTION (around lines 179-198):
OLD_SMB_ML_CODE = '''
                ml_data = {
                    'command': command,
                    'path': '',  # Will be updated with actual path if available
                    'session_data': {
                        'read_ops': 1,
                        'write_ops': 0,
                        'delete_ops': 0,
                        'bytes_read': 0,
                        'bytes_written': 0,
                        'failed_ops': 0
                    }
                }
                ml_results = self.ml_detector.score(ml_data)
                analysis.update(ml_results)
                
                # Enhance severity based on ML anomaly score
                if ml_results.get('ml_anomaly_score', 0) > 0.8:
                    if analysis['severity'] in ['low', 'medium']:
                        analysis['severity'] = 'high'
                        analysis['attack_types'].append('ml_anomaly')
'''

# REPLACE WITH THIS COMPREHENSIVE PHASE 5 CODE:
NEW_SMB_ML_CODE = '''
                # Prepare comprehensive ML data (NO hardcoded values)
                ml_data = {
                    'command': command,
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
                
                logging.info(f"SMB ML Analysis: Score={ml_score:.3f}, Labels={ml_results.get('ml_labels', [])}, Confidence={ml_results.get('ml_confidence', 0):.3f}")
'''

# =============================================================================
# ALSO ADD ML-ENHANCED THREAT SCORING TO SMB
# =============================================================================

# FIND THE _calculate_threat_score METHOD AND ENHANCE IT:
OLD_SMB_THREAT_SCORE = '''
    def _calculate_threat_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate threat score based on analysis"""
        score = 0
        severity_scores = {'low': 10, 'medium': 30, 'high': 60, 'critical': 90}
        
        # Base score from severity
        score += severity_scores.get(analysis['severity'], 0)
        
        # Add points for multiple attack types
        score += len(analysis['attack_types']) * 5
        
        # Add points for vulnerabilities
        score += len(analysis['vulnerabilities']) * 15
        
        return min(score, 100)  # Cap at 100
'''

NEW_SMB_THREAT_SCORE = '''
    def _calculate_threat_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate threat score based on analysis including ML insights"""
        score = 0
        severity_scores = {'low': 10, 'medium': 30, 'high': 60, 'critical': 90}
        
        # Base score from severity
        score += severity_scores.get(analysis['severity'], 0)
        
        # Add points for multiple attack types
        score += len(analysis['attack_types']) * 5
        
        # Add points for vulnerabilities
        score += len(analysis['vulnerabilities']) * 15
        
        # Add ML-based scoring
        ml_score = analysis.get('ml_anomaly_score', 0)
        if ml_score > 0:
            # ML score contributes up to 30 points
            ml_contribution = int(ml_score * 30)
            score += ml_contribution
            
            # Bonus for high confidence ML detection
            ml_confidence = analysis.get('ml_confidence', 0)
            if ml_confidence > 0.8 and ml_score > 0.7:
                score += 10  # High confidence bonus
        
        return min(score, 100)  # Cap at 100
'''

# =============================================================================
# ALSO ENHANCE THE ERROR HANDLING SECTION
# =============================================================================

OLD_SMB_ERROR_HANDLING = '''
            except Exception as e:
                logging.error(f"ML analysis failed: {e}")
                if not config.get('ml', {}).get('fallback_on_error', True):
                    raise
'''

NEW_SMB_ERROR_HANDLING = '''
            except Exception as e:
                logging.error(f"ML analysis failed: {e}")
                # Add ML error information to analysis
                analysis['ml_error'] = str(e)
                analysis['ml_anomaly_score'] = 0.0
                analysis['ml_labels'] = ['ml_error']
                if not config.get('ml', {}).get('fallback_on_error', True):
                    raise
'''

print("✅ SMB ML Integration Fix Generated!")
print("📁 File: smb_ml_integration_fix.py")
print("\n🔧 Manual Steps Required:")
print("1. Open src/service_emulators/SMB/smb_server.py")
print("2. Find the ML section around lines 179-198")
print("3. Replace the old ML code with the new comprehensive code")
print("4. Update the _calculate_threat_score method")
print("5. Update the error handling section")
print("\n🎯 This will upgrade SMB to Phase 5 Complete ML Integration!")
