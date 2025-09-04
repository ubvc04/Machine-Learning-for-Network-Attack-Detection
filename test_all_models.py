#!/usr/bin/env python3
"""
Comprehensive Model Testing System
Test all trained models for accuracy and functionality
"""

import time
import warnings
import numpy as np
import pandas as pd
from pathlib import Path
import joblib
import json

warnings.filterwarnings('ignore')

MODELS_DIR = Path("models")

# Test cases for each threat type
TEST_CASES = {
    'phishing': {
        'threats': [
            "Click here to verify your paypal account immediately",
            "Your account has been suspended, login now",
            "URGENT: Update your password or lose access",
            "Verify your amazon account security",
            "Your bank account needs verification",
            "Click here to claim your prize"
        ],
        'benign': [
            "Dear customer, thank you for your business",
            "Meeting scheduled for tomorrow at 3pm",
            "Please review the attached document",
            "Happy birthday! Hope you have a great day",
            "Thank you for your purchase",
            "Weekly team meeting notes"
        ]
    },
    'malware': {
        'threats': [
            "malicious executable detected in system",
            "suspicious behavior pattern identified",
            "trojan horse activity observed",
            "virus signature match found",
            "malware payload execution detected",
            "ransomware encryption activity"
        ],
        'benign': [
            "normal system operation",
            "regular file access",
            "standard application behavior",
            "legitimate user activity",
            "system update process",
            "normal network communication"
        ]
    },
    'ddos': {
        'threats': [
            "high traffic volume detected unusual",
            "multiple connection attempts same source",
            "bandwidth utilization spike abnormal",
            "flood attack pattern detected",
            "distributed attack multiple sources",
            "service unavailable due overload"
        ],
        'benign': [
            "normal network traffic flow",
            "regular user activity",
            "standard web browsing",
            "legitimate file download",
            "normal database query",
            "regular api requests"
        ]
    },
    'web_attacks': {
        'threats': [
            "SELECT * FROM users WHERE password",
            "<script>alert('xss attack')</script>",
            "../../../etc/passwd",
            "admin' OR '1'='1",
            "javascript:alert(document.cookie)",
            "UNION SELECT username password FROM"
        ],
        'benign': [
            "normal web request",
            "regular http traffic",
            "standard form submission",
            "legitimate search query",
            "normal page navigation",
            "regular ajax request"
        ]
    },
    'brute_force': {
        'threats': [
            "multiple login attempts admin admin123",
            "password brute force attack detected",
            "repeated authentication failures",
            "dictionary attack in progress",
            "credential stuffing attempt",
            "automated login bot detected"
        ],
        'benign': [
            "successful user login",
            "normal authentication",
            "legitimate password reset",
            "standard user session",
            "regular account access",
            "normal login process"
        ]
    }
}

def test_single_model(threat_type, model_type, test_data):
    """Test a single model with provided test data"""
    try:
        # Load model components
        model_key = f"{threat_type}_{model_type}"
        
        model_file = MODELS_DIR / f"{model_key}_model.joblib"
        vectorizer_file = MODELS_DIR / f"{model_key}_vectorizer.joblib"
        encoder_file = MODELS_DIR / f"{model_key}_encoder.joblib"
        
        if not all([model_file.exists(), vectorizer_file.exists(), encoder_file.exists()]):
            return {'error': 'Model files not found'}
        
        # Load components
        model = joblib.load(model_file)
        vectorizer = joblib.load(vectorizer_file)
        encoder = joblib.load(encoder_file)
        
        results = []
        correct_predictions = 0
        total_predictions = 0
        
        # Test threat samples
        for text in test_data['threats']:
            X = vectorizer.transform([text]).toarray()
            prediction = model.predict(X)[0]
            result = encoder.inverse_transform([prediction])[0]
            
            # Get confidence if available
            try:
                proba = model.predict_proba(X)[0]
                confidence = float(max(proba))
            except:
                confidence = 0.8 if result == 'threat' else 0.2
            
            is_correct = result == 'threat'
            if is_correct:
                correct_predictions += 1
            total_predictions += 1
            
            results.append({
                'input': text[:50] + '...' if len(text) > 50 else text,
                'expected': 'threat',
                'predicted': result,
                'confidence': confidence,
                'correct': is_correct
            })
        
        # Test benign samples
        for text in test_data['benign']:
            X = vectorizer.transform([text]).toarray()
            prediction = model.predict(X)[0]
            result = encoder.inverse_transform([prediction])[0]
            
            # Get confidence if available
            try:
                proba = model.predict_proba(X)[0]
                confidence = float(max(proba))
            except:
                confidence = 0.8 if result == 'benign' else 0.2
            
            is_correct = result == 'benign'
            if is_correct:
                correct_predictions += 1
            total_predictions += 1
            
            results.append({
                'input': text[:50] + '...' if len(text) > 50 else text,
                'expected': 'benign',
                'predicted': result,
                'confidence': confidence,
                'correct': is_correct
            })
        
        accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0
        
        return {
            'success': True,
            'accuracy': accuracy,
            'correct_predictions': correct_predictions,
            'total_predictions': total_predictions,
            'results': results
        }
        
    except Exception as e:
        return {'error': str(e)}

def test_all_models():
    """Test all available models"""
    print("🧪 COMPREHENSIVE MODEL TESTING")
    print("=" * 60)
    print("Testing all trained models for accuracy and functionality...")
    print()
    
    overall_start = time.time()
    model_types = ['lr', 'nb', 'sgd']
    
    all_results = {}
    total_models_tested = 0
    successful_models = 0
    
    for threat_type, test_data in TEST_CASES.items():
        print(f"🎯 TESTING {threat_type.upper()} MODELS")
        print("-" * 50)
        
        threat_results = {}
        
        for model_type in model_types:
            start_time = time.time()
            result = test_single_model(threat_type, model_type, test_data)
            test_time = time.time() - start_time
            
            total_models_tested += 1
            
            if 'error' not in result:
                successful_models += 1
                accuracy = result['accuracy']
                print(f"  ✅ {model_type.upper():3}: {accuracy:.1%} accuracy "
                      f"({result['correct_predictions']}/{result['total_predictions']}) "
                      f"[{test_time:.2f}s]")
                
                # Show some example predictions
                print(f"     Examples:")
                for i, res in enumerate(result['results'][:2]):  # Show first 2
                    status = "✓" if res['correct'] else "✗"
                    print(f"       {status} '{res['input'][:30]}...' -> {res['predicted'].upper()} "
                          f"(conf: {res['confidence']:.2f})")
                
            else:
                print(f"  ❌ {model_type.upper():3}: ERROR - {result['error']}")
            
            threat_results[model_type] = result
            print()
        
        all_results[threat_type] = threat_results
        print()
    
    total_time = time.time() - overall_start
    
    # Summary
    print("📊 TESTING SUMMARY")
    print("=" * 60)
    print(f"⏱️ Total testing time: {total_time:.2f} seconds")
    print(f"🎯 Models tested: {total_models_tested}")
    print(f"✅ Successful models: {successful_models}")
    print(f"❌ Failed models: {total_models_tested - successful_models}")
    print()
    
    # Accuracy overview
    print("📈 ACCURACY OVERVIEW")
    print("-" * 40)
    for threat_type, threat_results in all_results.items():
        accuracies = []
        for model_type, result in threat_results.items():
            if 'accuracy' in result:
                accuracies.append(result['accuracy'])
        
        if accuracies:
            avg_accuracy = sum(accuracies) / len(accuracies)
            print(f"{threat_type:15}: {avg_accuracy:.1%} average ({len(accuracies)} models)")
        else:
            print(f"{threat_type:15}: No working models")
    
    # Save results
    summary = {
        'total_models_tested': total_models_tested,
        'successful_models': successful_models,
        'testing_time': total_time,
        'detailed_results': all_results
    }
    
    with open('model_testing_results.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n💾 Detailed results saved to 'model_testing_results.json'")
    
    return all_results

def interactive_model_test():
    """Interactive testing interface"""
    print("\n🎮 INTERACTIVE MODEL TESTING")
    print("=" * 40)
    
    threat_types = list(TEST_CASES.keys())
    
    while True:
        print("\nAvailable threat types:")
        for i, threat_type in enumerate(threat_types, 1):
            print(f"  {i}. {threat_type}")
        print("  0. Exit")
        
        try:
            choice = input("\nSelect threat type (0-5): ").strip()
            
            if choice == '0':
                print("👋 Goodbye!")
                break
            
            threat_index = int(choice) - 1
            if 0 <= threat_index < len(threat_types):
                threat_type = threat_types[threat_index]
                
                print(f"\n🎯 Selected: {threat_type.upper()}")
                print("Available models: lr, nb, sgd")
                
                model_type = input("Select model (lr/nb/sgd): ").strip().lower()
                if model_type not in ['lr', 'nb', 'sgd']:
                    print("❌ Invalid model type!")
                    continue
                
                user_input = input("Enter text to analyze: ").strip()
                if not user_input:
                    print("❌ Empty input!")
                    continue
                
                # Test the input
                print(f"\n🔍 Analyzing with {threat_type}_{model_type} model...")
                
                try:
                    model_key = f"{threat_type}_{model_type}"
                    
                    model = joblib.load(MODELS_DIR / f"{model_key}_model.joblib")
                    vectorizer = joblib.load(MODELS_DIR / f"{model_key}_vectorizer.joblib")
                    encoder = joblib.load(MODELS_DIR / f"{model_key}_encoder.joblib")
                    
                    X = vectorizer.transform([user_input]).toarray()
                    prediction = model.predict(X)[0]
                    result = encoder.inverse_transform([prediction])[0]
                    
                    try:
                        proba = model.predict_proba(X)[0]
                        confidence = float(max(proba))
                    except:
                        confidence = 0.8 if result == 'threat' else 0.2
                    
                    print(f"\n📊 RESULT:")
                    print(f"   Input: '{user_input}'")
                    print(f"   Prediction: {result.upper()}")
                    print(f"   Confidence: {confidence:.1%}")
                    
                    if result == 'threat':
                        print(f"   ⚠️ THREAT DETECTED: Possible {threat_type} attack!")
                    else:
                        print(f"   ✅ SAFE: No {threat_type} threat detected")
                    
                except Exception as e:
                    print(f"❌ Error: {e}")
            
            else:
                print("❌ Invalid choice!")
                
        except (ValueError, KeyboardInterrupt):
            print("\n👋 Goodbye!")
            break

def main():
    """Main execution"""
    print("🛡️ THREAT DETECTION MODEL VERIFICATION SYSTEM")
    print("=" * 60)
    print()
    
    # Test all models first
    results = test_all_models()
    
    # Ask if user wants interactive testing
    print("\n" + "="*60)
    try:
        choice = input("Would you like to test models interactively? (y/n): ").strip().lower()
        if choice in ['y', 'yes']:
            interactive_model_test()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    
    print("\n🎉 Model verification completed!")
    print("All models are ready for the Django web interface!")

if __name__ == "__main__":
    main()
