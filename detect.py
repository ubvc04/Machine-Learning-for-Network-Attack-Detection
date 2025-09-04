"""
Threat Detection System - Detection Engine Module
Hybrid detection system combining signature-based and ML-based detection
"""

import pandas as pd
import numpy as np
import joblib
import json
import re
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
import warnings
import logging

# ML libraries
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer

# Text processing
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

from config import *

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

warnings.filterwarnings('ignore')

class SignatureDetector:
    """
    Signature-based detection using rules and patterns
    """
    
    def __init__(self):
        self.rules = self._load_detection_rules()
        self.suspicious_patterns = self._get_suspicious_patterns()
    
    def _load_detection_rules(self) -> Dict[str, List[str]]:
        """Load detection rules from rules directory"""
        rules = {
            'malware_hashes': [],
            'phishing_domains': [],
            'malicious_ips': [],
            'attack_patterns': []
        }
        
        # Load rules from files if they exist
        rules_files = {
            'malware_hashes': RULES_DIR / 'malware_hashes.txt',
            'phishing_domains': RULES_DIR / 'phishing_domains.txt',
            'malicious_ips': RULES_DIR / 'malicious_ips.txt',
            'attack_patterns': RULES_DIR / 'attack_patterns.txt'
        }
        
        for rule_type, file_path in rules_files.items():
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        rules[rule_type] = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    logger.warning(f"Could not load {rule_type}: {e}")
        
        return rules
    
    def _get_suspicious_patterns(self) -> Dict[str, List[str]]:
        """Define suspicious patterns for different attack types"""
        return {
            'sql_injection': [
                r"(?i)(union.*select|select.*from|insert.*into|delete.*from)",
                r"(?i)(drop.*table|create.*table|alter.*table)",
                r"(?i)(\bor\b.*=.*\b|\band\b.*=.*\b)",
                r"(?i)(exec\(|execute\(|sp_executesql)"
            ],
            'xss': [
                r"(?i)(<script.*>|</script>)",
                r"(?i)(javascript:|vbscript:|onload=|onerror=)",
                r"(?i)(alert\(|confirm\(|prompt\()",
                r"(?i)(<iframe.*>|<object.*>|<embed.*>)"
            ],
            'command_injection': [
                r"(?i)(;.*ls|;.*cat|;.*rm|;.*mv)",
                r"(?i)(\|\s*ls|\|\s*cat|\|\s*rm|\|\s*mv)",
                r"(?i)(&&.*ls|&&.*cat|&&.*rm|&&.*mv)",
                r"(?i)(wget|curl|nc|netcat)"
            ],
            'directory_traversal': [
                r"\.\.\/",
                r"\.\.\\",
                r"(?i)(etc\/passwd|etc\/shadow|boot\.ini)",
                r"(?i)(\.\.%2f|\.\.%5c)"
            ],
            'brute_force': [
                r"(?i)(admin|administrator|root|guest)",
                r"(?i)(password|passwd|pwd|pass)",
                r"(?i)(login|signin|auth|authentication)"
            ],
            'phishing': [
                r"(?i)(urgent.*action|account.*suspended|verify.*account)",
                r"(?i)(click.*here|update.*information|confirm.*identity)",
                r"(?i)(security.*alert|suspicious.*activity|unauthorized.*access)",
                r"(?i)(paypal|amazon|microsoft|google|apple).*security"
            ]
        }
    
    def detect_patterns(self, text: str) -> Dict[str, Any]:
        """Detect malicious patterns in text"""
        if not text or pd.isna(text):
            return {'detected': False, 'attack_types': [], 'confidence': 0.0}
        
        text = str(text)
        detected_attacks = []
        total_matches = 0
        
        for attack_type, patterns in self.suspicious_patterns.items():
            matches = 0
            for pattern in patterns:
                if re.search(pattern, text):
                    matches += 1
                    total_matches += 1
            
            if matches > 0:
                detected_attacks.append({
                    'type': attack_type,
                    'matches': matches,
                    'confidence': min(matches / len(patterns), 1.0)
                })
        
        overall_confidence = min(total_matches / 3, 1.0)  # Lower denominator for better confidence
        
        return {
            'detected': len(detected_attacks) > 0,
            'attack_types': detected_attacks,
            'confidence': overall_confidence
        }
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP against known malicious IPs"""
        if ip in self.rules['malicious_ips']:
            return {
                'detected': True,
                'threat_type': 'malicious_ip',
                'confidence': 1.0
            }
        
        # Check for suspicious IP patterns
        suspicious_patterns = [
            r'^10\.',      # Private IP ranges (might be suspicious in some contexts)
            r'^192\.168\.', 
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^0\.',       # Invalid IPs
            r'^127\.',     # Localhost
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, ip):
                return {
                    'detected': True,
                    'threat_type': 'suspicious_ip_pattern',
                    'confidence': 0.5
                }
        
        return {'detected': False, 'threat_type': None, 'confidence': 0.0}
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain against known phishing domains"""
        if domain in self.rules['phishing_domains']:
            return {
                'detected': True,
                'threat_type': 'phishing_domain',
                'confidence': 1.0
            }
        
        # Check for suspicious domain patterns
        suspicious_patterns = [
            r'.*-.*-.*-.*',  # Multiple hyphens
            r'.*\d{4,}.*',   # Long numbers in domain
            r'.*\.tk$|.*\.ml$|.*\.ga$',  # Suspicious TLDs
            r'.*paypal.*|.*amazon.*|.*microsoft.*'  # Brand impersonation
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, domain.lower()):
                return {
                    'detected': True,
                    'threat_type': 'suspicious_domain_pattern',
                    'confidence': 0.6
                }
        
        return {'detected': False, 'threat_type': None, 'confidence': 0.0}

class MLDetector:
    """
    Machine Learning-based threat detection
    """
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.vectorizers = {}
        self.feature_names = {}
        self.model_metadata = {}
        self._load_models()
    
    def _load_models(self):
        """Load all trained models and their metadata"""
        logger.info("Loading trained models...")
        
        # Find all model files
        model_files = list(MODELS_DIR.glob("*.joblib"))
        metadata_files = list(MODELS_DIR.glob("*_metadata.json"))
        
        for metadata_file in metadata_files:
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                model_key = f"{metadata['classification_type']}_{metadata['model_name']}"
                model_path = Path(metadata['model_path'])
                
                if model_path.exists():
                    model = joblib.load(model_path)
                    self.models[model_key] = model
                    self.model_metadata[model_key] = metadata
                    self.feature_names[model_key] = metadata['feature_names']
                    
                    logger.info(f"Loaded model: {model_key}")
                else:
                    logger.warning(f"Model file not found: {model_path}")
                    
            except Exception as e:
                logger.error(f"Error loading model metadata {metadata_file}: {e}")
        
        logger.info(f"Loaded {len(self.models)} models")
    
    def _preprocess_features(self, data: pd.DataFrame, model_key: str) -> np.ndarray:
        """Preprocess features for ML prediction"""
        try:
            expected_features = self.feature_names[model_key]
            
            # Ensure all expected features are present
            for feature in expected_features:
                if feature not in data.columns:
                    data[feature] = 0
            
            # Select only expected features in correct order
            features = data[expected_features].fillna(0)
            
            return features.values
            
        except Exception as e:
            logger.error(f"Error preprocessing features for {model_key}: {e}")
            return np.array([])
    
    def predict_threat(self, features: pd.DataFrame, 
                      classification_type: str = 'binary') -> Dict[str, Any]:
        """Predict threats using ML models"""
        predictions = {}
        
        # Get models for the specified classification type
        relevant_models = {k: v for k, v in self.models.items() 
                          if k.startswith(classification_type)}
        
        if not relevant_models:
            logger.warning(f"No models found for classification type: {classification_type}")
            return predictions
        
        for model_key, model in relevant_models.items():
            try:
                # Preprocess features
                X = self._preprocess_features(features, model_key)
                
                if X.size == 0:
                    continue
                
                # Make prediction
                pred = model.predict(X)
                pred_proba = None
                
                try:
                    pred_proba = model.predict_proba(X)
                except:
                    pass
                
                predictions[model_key] = {
                    'prediction': pred[0] if len(pred) > 0 else 0,
                    'probability': pred_proba[0] if pred_proba is not None else None,
                    'confidence': np.max(pred_proba[0]) if pred_proba is not None else 0.5,
                    'model_metadata': self.model_metadata[model_key]
                }
                
            except Exception as e:
                logger.error(f"Error making prediction with {model_key}: {e}")
        
        return predictions
    
    def ensemble_prediction(self, predictions: Dict[str, Any]) -> Dict[str, Any]:
        """Combine predictions from multiple models using ensemble voting"""
        if not predictions:
            return {'prediction': 0, 'confidence': 0.0, 'threat_type': 'BENIGN'}
        
        # Collect all predictions and confidences
        pred_values = []
        confidences = []
        
        for model_key, pred_data in predictions.items():
            pred_values.append(pred_data['prediction'])
            confidences.append(pred_data['confidence'])
        
        # Majority voting for prediction
        final_prediction = 1 if np.mean(pred_values) > 0.5 else 0
        
        # Average confidence
        final_confidence = np.mean(confidences)
        
        # Determine threat type based on prediction
        threat_type = 'ATTACK' if final_prediction == 1 else 'BENIGN'
        
        return {
            'prediction': final_prediction,
            'confidence': final_confidence,
            'threat_type': threat_type,
            'individual_predictions': predictions
        }

class HybridThreatDetector:
    """
    Hybrid threat detection system combining signature and ML detection
    """
    
    def __init__(self):
        self.signature_detector = SignatureDetector()
        self.ml_detector = MLDetector()
        self.alert_history = []
    
    def detect_threats(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive threat detection on input data
        """
        detection_results = {
            'timestamp': datetime.now().isoformat(),
            'input_data': data,
            'signature_detection': {},
            'ml_detection': {},
            'final_verdict': {},
            'alerts': []
        }
        
        # Signature-based detection
        if 'text' in data:
            sig_result = self.signature_detector.detect_patterns(data['text'])
            detection_results['signature_detection']['pattern_analysis'] = sig_result
        
        if 'ip' in data:
            ip_result = self.signature_detector.check_ip_reputation(data['ip'])
            detection_results['signature_detection']['ip_reputation'] = ip_result
        
        if 'domain' in data:
            domain_result = self.signature_detector.check_domain_reputation(data['domain'])
            detection_results['signature_detection']['domain_reputation'] = domain_result
        
        # ML-based detection
        if 'features' in data:
            features_df = pd.DataFrame([data['features']]) if isinstance(data['features'], dict) else data['features']
            
            # Binary classification
            binary_predictions = self.ml_detector.predict_threat(features_df, 'binary')
            binary_ensemble = self.ml_detector.ensemble_prediction(binary_predictions)
            detection_results['ml_detection']['binary'] = binary_ensemble
            
            # Multi-class classification
            multiclass_predictions = self.ml_detector.predict_threat(features_df, 'multiclass')
            multiclass_ensemble = self.ml_detector.ensemble_prediction(multiclass_predictions)
            detection_results['ml_detection']['multiclass'] = multiclass_ensemble
        
        # Combine results for final verdict
        final_verdict = self._combine_detection_results(detection_results)
        detection_results['final_verdict'] = final_verdict
        
        # Generate alerts if threats detected
        if final_verdict['is_threat']:
            alert = self._generate_alert(detection_results)
            detection_results['alerts'].append(alert)
            self.alert_history.append(alert)
        
        return detection_results
    
    def _combine_detection_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Combine signature and ML detection results"""
        signature_threat = False
        ml_threat = False
        overall_confidence = 0.0
        threat_types = []
        
        # Check signature detection results
        sig_detection = results['signature_detection']
        if sig_detection:
            for detection_type, result in sig_detection.items():
                if result.get('detected', False):
                    signature_threat = True
                    overall_confidence = max(overall_confidence, result.get('confidence', 0.0))
                    
                    if 'attack_types' in result:
                        threat_types.extend([at['type'] for at in result['attack_types']])
                    elif 'threat_type' in result:
                        threat_types.append(result['threat_type'])
        
        # Check ML detection results
        ml_detection = results['ml_detection']
        if ml_detection:
            for detection_type, result in ml_detection.items():
                if result.get('prediction', 0) == 1:
                    ml_threat = True
                    overall_confidence = max(overall_confidence, result.get('confidence', 0.0))
                    threat_types.append(result.get('threat_type', 'UNKNOWN'))
        
        # Final decision
        is_threat = signature_threat or ml_threat
        confidence_threshold = ALERT_CONFIG['confidence_threshold']
        
        # Adjust confidence based on agreement between methods
        if signature_threat and ml_threat:
            overall_confidence = min(overall_confidence * 1.2, 1.0)  # Boost confidence
        elif signature_threat or ml_threat:
            overall_confidence = overall_confidence * 0.9  # Slight reduction
        
        return {
            'is_threat': is_threat and overall_confidence >= confidence_threshold,
            'confidence': overall_confidence,
            'threat_types': list(set(threat_types)),
            'signature_detected': signature_threat,
            'ml_detected': ml_threat,
            'severity': self._calculate_severity(overall_confidence)
        }
    
    def _calculate_severity(self, confidence: float) -> str:
        """Calculate threat severity based on confidence"""
        severity_levels = ALERT_CONFIG['severity_levels']
        
        if confidence >= severity_levels['CRITICAL']:
            return 'CRITICAL'
        elif confidence >= severity_levels['HIGH']:
            return 'HIGH'
        elif confidence >= severity_levels['MEDIUM']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_alert(self, detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate structured alert from detection results"""
        final_verdict = detection_results['final_verdict']
        input_data = detection_results['input_data']
        
        alert = {
            'id': hashlib.md5(str(detection_results).encode()).hexdigest()[:8],
            'timestamp': detection_results['timestamp'],
            'severity': final_verdict['severity'],
            'confidence': final_verdict['confidence'],
            'threat_types': final_verdict['threat_types'],
            'source_ip': input_data.get('ip', 'unknown'),
            'source_domain': input_data.get('domain', 'unknown'),
            'detection_method': [],
            'raw_data': input_data
        }
        
        if final_verdict['signature_detected']:
            alert['detection_method'].append('signature')
        if final_verdict['ml_detected']:
            alert['detection_method'].append('machine_learning')
        
        # Format alert message
        primary_threat = final_verdict['threat_types'][0] if final_verdict['threat_types'] else 'UNKNOWN'
        alert['message'] = ALERT_CONFIG['log_format'].format(
            timestamp=alert['timestamp'],
            severity=alert['severity'],
            attack_type=primary_threat,
            source=alert['source_ip'],
            confidence=alert['confidence']
        )
        
        return alert
    
    def process_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Process a file for threat detection"""
        logger.info(f"Processing file: {file_path}")
        
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        results = []
        
        if file_path.suffix.lower() == '.csv':
            # Process CSV file
            df = pd.read_csv(file_path)
            
            for idx, row in df.iterrows():
                data = {
                    'features': row.to_dict(),
                    'source': f"{file_path.name}:row_{idx}"
                }
                
                # Add text data if available
                text_columns = [col for col in df.columns if df[col].dtype == 'object']
                if text_columns:
                    data['text'] = ' '.join([str(row[col]) for col in text_columns])
                
                detection_result = self.detect_threats(data)
                results.append(detection_result)
        
        elif file_path.suffix.lower() == '.txt':
            # Process text file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            data = {
                'text': content,
                'source': file_path.name
            }
            
            detection_result = self.detect_threats(data)
            results.append(detection_result)
        
        logger.info(f"Processed {len(results)} items from {file_path}")
        return results
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of all alerts"""
        if not self.alert_history:
            return {'total_alerts': 0}
        
        severity_counts = {}
        threat_type_counts = {}
        
        for alert in self.alert_history:
            # Count by severity
            severity = alert['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by threat types
            for threat_type in alert['threat_types']:
                threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
        
        return {
            'total_alerts': len(self.alert_history),
            'severity_distribution': severity_counts,
            'threat_type_distribution': threat_type_counts,
            'latest_alert': self.alert_history[-1] if self.alert_history else None
        }

def main():
    """Demo of the threat detection system"""
    detector = HybridThreatDetector()
    
    # Example 1: Text-based detection
    print("Testing text-based detection...")
    text_data = {
        'text': "Please update your paypal account by clicking here: http://paypal-security.tk/login",
        'source': 'email_sample'
    }
    result1 = detector.detect_threats(text_data)
    print(f"Result 1: {result1['final_verdict']}")
    
    # Example 2: Network-based detection
    print("\nTesting network-based detection...")
    network_data = {
        'ip': '192.168.1.100',
        'domain': 'amazon-security.ml',
        'source': 'network_traffic'
    }
    result2 = detector.detect_threats(network_data)
    print(f"Result 2: {result2['final_verdict']}")
    
    # Display alert summary
    print("\nAlert Summary:")
    summary = detector.get_alert_summary()
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
