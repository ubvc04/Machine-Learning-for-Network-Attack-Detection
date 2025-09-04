#!/usr/bin/env python3
"""
🔍 COMPREHENSIVE THREAT DETECTION CLI TESTER
=============================================
Interactive CLI tool for testing all trained models with custom inputs.
Supports all 11 threat types with realistic testing scenarios.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class ThreatDetectionCLI:
    def __init__(self):
        self.models = {}
        self.encoders = {}
        self.scalers = {}
        self.vectorizers = {}
        self.threat_types = []
        self.load_models()
        
    def load_models(self):
        """Load all trained models and preprocessors"""
        print("🔄 Loading threat detection models...")
        
        # Find all threat types
        model_files = [f for f in os.listdir('models') if f.endswith('_model.joblib')]
        
        for model_file in model_files:
            parts = model_file.replace('_model.joblib', '').split('_')
            algorithm = parts[-1]
            threat_type = '_'.join(parts[:-1])
            
            if threat_type not in self.threat_types:
                self.threat_types.append(threat_type)
            
            # Load model
            model_key = f"{threat_type}_{algorithm}"
            try:
                self.models[model_key] = joblib.load(f'models/{model_file}')
                
                # Load preprocessors
                if threat_type not in self.encoders:
                    encoder_file = f'models/{threat_type}_encoder.joblib'
                    if os.path.exists(encoder_file):
                        self.encoders[threat_type] = joblib.load(encoder_file)
                
                if threat_type not in self.scalers:
                    scaler_file = f'models/{threat_type}_scaler.joblib'
                    if os.path.exists(scaler_file):
                        self.scalers[threat_type] = joblib.load(scaler_file)
                
                if threat_type not in self.vectorizers:
                    vectorizer_file = f'models/{threat_type}_vectorizer.joblib'
                    if os.path.exists(vectorizer_file):
                        self.vectorizers[threat_type] = joblib.load(vectorizer_file)
                        
            except Exception as e:
                print(f"❌ Error loading {model_file}: {e}")
        
        self.threat_types = sorted([t for t in self.threat_types if not t.startswith(('fast', 'lightning'))])
        print(f"✅ Loaded models for {len(self.threat_types)} threat types")
        
    def get_sample_inputs(self):
        """Provide sample inputs for different threat types"""
        samples = {
            'phishing': [
                "URGENT: Your account will be suspended! Click here to verify: http://fake-bank.com",
                "Congratulations! You've won $1,000,000! Send your SSN to claim your prize!",
                "Dear customer, suspicious activity detected. Update your password immediately.",
                "Hi, this is a legitimate business email about our quarterly meeting."
            ],
            'malware': [
                "High memory usage pattern with unusual process injection",
                "Normal system operation with standard processes",
                "Suspicious registry modifications and network connections",
                "Legitimate software installation and updates"
            ],
            'ddos': [
                "High volume network traffic from multiple sources",
                "Normal web browsing traffic",
                "Coordinated requests overwhelming server resources",
                "Regular API calls within normal limits"
            ],
            'web_attacks': [
                "SQL injection attempt: ' OR 1=1 --",
                "Cross-site scripting: <script>alert('XSS')</script>",
                "Brute force login attempts with password lists",
                "Normal user login and browsing"
            ],
            'brute_force': [
                "Multiple failed SSH login attempts from same IP",
                "Successful authentication after normal retry",
                "FTP password spraying attack detected",
                "Regular file transfer operations"
            ],
            'port_scan': [
                "Sequential port probing on target system",
                "Normal network service connections",
                "Stealth scan attempting to avoid detection",
                "Legitimate network diagnostic tools"
            ],
            'infiltration': [
                "Lateral movement between network segments",
                "Standard inter-system communications",
                "Data exfiltration patterns detected",
                "Normal backup and sync operations"
            ],
            'dos_attacks': [
                "Slowloris attack keeping connections open",
                "Normal HTTP request patterns",
                "HTTP flood overwhelming web server",
                "Regular website usage patterns"
            ],
            'bot_attacks': [
                "Automated behavior patterns detected",
                "Human-like interaction patterns",
                "Command and control communications",
                "Normal software update checks"
            ],
            'network_baseline': [
                "Unusual network traffic patterns",
                "Standard network operations",
                "Anomalous data transfer volumes",
                "Regular business network activity"
            ],
            'ddos_friday': [
                "Friday afternoon DDoS attack pattern",
                "Normal Friday business traffic",
                "Weekend preparation network load",
                "End-of-week backup operations"
            ]
        }
        return samples
    
    def predict_text_threat(self, threat_type, text_input):
        """Predict threat for text-based inputs"""
        try:
            # Get available algorithms for this threat type
            available_models = [k for k in self.models.keys() if k.startswith(f"{threat_type}_")]
            
            if not available_models:
                return {"error": f"No models found for {threat_type}"}
            
            results = {}
            
            for model_key in available_models:
                algorithm = model_key.split('_')[-1]
                
                # Vectorize text
                if threat_type in self.vectorizers:
                    X_vectorized = self.vectorizers[threat_type].transform([text_input])
                    
                    # Predict
                    model = self.models[model_key]
                    prediction = model.predict(X_vectorized)[0]
                    probability = model.predict_proba(X_vectorized)[0] if hasattr(model, 'predict_proba') else None
                    
                    # Decode prediction
                    if threat_type in self.encoders:
                        prediction_label = self.encoders[threat_type].inverse_transform([prediction])[0]
                    else:
                        prediction_label = prediction
                    
                    results[algorithm] = {
                        'prediction': prediction_label,
                        'confidence': float(max(probability)) if probability is not None else None
                    }
                    
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def predict_numeric_threat(self, threat_type, description):
        """Predict threat for numeric-based inputs (simulated from description)"""
        try:
            # Get available algorithms for this threat type
            available_models = [k for k in self.models.keys() if k.startswith(f"{threat_type}_")]
            
            if not available_models:
                return {"error": f"No models found for {threat_type}"}
            
            # Create synthetic numeric features based on description keywords
            features = self.generate_synthetic_features(description, threat_type)
            
            results = {}
            
            for model_key in available_models:
                algorithm = model_key.split('_')[-1]
                
                # Scale features if scaler exists
                if threat_type in self.scalers:
                    X_scaled = self.scalers[threat_type].transform([features])
                else:
                    X_scaled = np.array([features])
                
                # Predict
                model = self.models[model_key]
                prediction = model.predict(X_scaled)[0]
                probability = model.predict_proba(X_scaled)[0] if hasattr(model, 'predict_proba') else None
                
                # Decode prediction
                if threat_type in self.encoders:
                    prediction_label = self.encoders[threat_type].inverse_transform([prediction])[0]
                else:
                    prediction_label = prediction
                
                results[algorithm] = {
                    'prediction': prediction_label,
                    'confidence': float(max(probability)) if probability is not None else None
                }
                
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def generate_synthetic_features(self, description, threat_type):
        """Generate synthetic numeric features based on text description"""
        # Simple keyword-based feature generation
        threat_keywords = {
            'ddos': ['flood', 'volume', 'traffic', 'multiple', 'overwhelming'],
            'port_scan': ['scan', 'probe', 'sequential', 'stealth'],
            'brute_force': ['multiple', 'failed', 'attempts', 'password'],
            'infiltration': ['lateral', 'movement', 'exfiltration'],
            'dos_attacks': ['slow', 'connections', 'flood', 'overwhelm'],
            'bot_attacks': ['automated', 'behavior', 'command', 'control'],
            'web_attacks': ['injection', 'script', 'attack', 'malicious'],
            'malware': ['suspicious', 'injection', 'unusual', 'modifications'],
            'network_baseline': ['unusual', 'anomalous', 'patterns', 'volumes']
        }
        
        desc_lower = description.lower()
        
        # Generate 20 features (matching typical network data)
        features = []
        
        # Keyword-based features
        keywords = threat_keywords.get(threat_type, [])
        for keyword in keywords[:5]:
            features.append(1.0 if keyword in desc_lower else 0.0)
        
        # Add random network-like features
        np.random.seed(hash(description) % 2**32)
        
        # Traffic volume features
        if any(word in desc_lower for word in ['high', 'flood', 'volume', 'multiple']):
            features.extend(np.random.uniform(800, 1000, 5))  # High values
        else:
            features.extend(np.random.uniform(10, 100, 5))   # Normal values
        
        # Timing features
        if any(word in desc_lower for word in ['slow', 'delay', 'timeout']):
            features.extend(np.random.uniform(5000, 10000, 5))  # Slow
        else:
            features.extend(np.random.uniform(10, 500, 5))     # Fast
        
        # Flag features
        if any(word in desc_lower for word in ['attack', 'malicious', 'suspicious']):
            features.extend(np.random.uniform(0.7, 1.0, 5))   # High flags
        else:
            features.extend(np.random.uniform(0.0, 0.3, 5))   # Low flags
        
        return features[:20]  # Ensure exactly 20 features
    
    def display_menu(self):
        """Display the main menu"""
        print("\n" + "="*60)
        print("🛡️  THREAT DETECTION SYSTEM - CLI TESTER")
        print("="*60)
        print("Available threat types:")
        
        for i, threat_type in enumerate(self.threat_types, 1):
            model_count = len([k for k in self.models.keys() if k.startswith(f"{threat_type}_")])
            print(f"  {i:2d}. {threat_type:20} ({model_count} models)")
        
        print(f"\n  {len(self.threat_types)+1:2d}. Test all models")
        print(f"  {len(self.threat_types)+2:2d}. Use sample inputs")
        print(f"   0. Exit")
        print("-"*60)
    
    def test_single_threat(self, threat_type):
        """Test a specific threat type"""
        print(f"\n🎯 Testing {threat_type.upper()} Detection")
        print("-" * 50)
        
        print("Enter your test input (or 'back' to return):")
        user_input = input(">>> ").strip()
        
        if user_input.lower() == 'back':
            return
        
        if user_input:
            print(f"\n🔍 Analyzing: '{user_input}'")
            print("-" * 40)
            
            # Determine if this is text-based or numeric-based threat
            text_based_threats = ['phishing']
            
            if threat_type in text_based_threats:
                results = self.predict_text_threat(threat_type, user_input)
            else:
                results = self.predict_numeric_threat(threat_type, user_input)
            
            if 'error' in results:
                print(f"❌ Error: {results['error']}")
            else:
                print("📊 Results:")
                for algorithm, result in results.items():
                    prediction = result['prediction']
                    confidence = result.get('confidence')
                    
                    status = "🚨" if prediction != 'benign' and prediction != 'legitimate' else "✅"
                    conf_str = f" ({confidence:.3f})" if confidence else ""
                    
                    print(f"   {algorithm.upper():4}: {status} {prediction}{conf_str}")
    
    def test_all_models(self):
        """Test all models with a single input"""
        print(f"\n🌐 Testing ALL Models")
        print("-" * 50)
        
        print("Enter your test input (or 'back' to return):")
        user_input = input(">>> ").strip()
        
        if user_input.lower() == 'back':
            return
        
        if user_input:
            print(f"\n🔍 Analyzing across all threat types: '{user_input}'")
            print("=" * 60)
            
            for threat_type in self.threat_types:
                print(f"\n🎯 {threat_type.upper()}")
                print("-" * 30)
                
                # Determine prediction method
                text_based_threats = ['phishing']
                
                if threat_type in text_based_threats:
                    results = self.predict_text_threat(threat_type, user_input)
                else:
                    results = self.predict_numeric_threat(threat_type, user_input)
                
                if 'error' in results:
                    print(f"   ❌ Error: {results['error']}")
                else:
                    for algorithm, result in results.items():
                        prediction = result['prediction']
                        confidence = result.get('confidence')
                        
                        status = "🚨" if prediction != 'benign' and prediction != 'legitimate' else "✅"
                        conf_str = f" ({confidence:.3f})" if confidence else ""
                        
                        print(f"   {algorithm.upper():4}: {status} {prediction}{conf_str}")
    
    def test_sample_inputs(self):
        """Test with predefined sample inputs"""
        print(f"\n📋 Testing with Sample Inputs")
        print("-" * 50)
        
        samples = self.get_sample_inputs()
        
        for threat_type in self.threat_types:
            if threat_type in samples:
                print(f"\n🎯 {threat_type.upper()} Samples:")
                
                for i, sample in enumerate(samples[threat_type][:2], 1):  # Test 2 samples per type
                    print(f"\n   Sample {i}: {sample}")
                    
                    # Determine prediction method
                    text_based_threats = ['phishing']
                    
                    if threat_type in text_based_threats:
                        results = self.predict_text_threat(threat_type, sample)
                    else:
                        results = self.predict_numeric_threat(threat_type, sample)
                    
                    if 'error' in results:
                        print(f"      ❌ Error: {results['error']}")
                    else:
                        for algorithm, result in results.items():
                            prediction = result['prediction']
                            status = "🚨" if prediction != 'benign' and prediction != 'legitimate' else "✅"
                            print(f"      {algorithm.upper()}: {status} {prediction}")
        
        input("\nPress Enter to continue...")
    
    def run(self):
        """Main CLI loop"""
        print("🚀 Starting Threat Detection CLI...")
        
        if not self.models:
            print("❌ No models loaded! Please train models first.")
            return
        
        while True:
            try:
                self.display_menu()
                choice = input("\nEnter your choice: ").strip()
                
                if choice == '0':
                    print("👋 Goodbye!")
                    break
                elif choice.isdigit():
                    choice_num = int(choice)
                    
                    if 1 <= choice_num <= len(self.threat_types):
                        threat_type = self.threat_types[choice_num - 1]
                        self.test_single_threat(threat_type)
                    elif choice_num == len(self.threat_types) + 1:
                        self.test_all_models()
                    elif choice_num == len(self.threat_types) + 2:
                        self.test_sample_inputs()
                    else:
                        print("❌ Invalid choice!")
                else:
                    print("❌ Please enter a number!")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Exiting...")
                break
            except Exception as e:
                print(f"❌ Error: {e}")

if __name__ == "__main__":
    cli = ThreatDetectionCLI()
    cli.run()
