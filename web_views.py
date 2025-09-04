"""
🌐 DJANGO VIEWS FOR THREAT DETECTION WEB INTERFACE
==================================================
Web views for the threat detection system with interactive testing.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import warnings
warnings.filterwarnings('ignore')

class ThreatDetectionEngine:
    """Core threat detection engine for web interface"""
    
    def __init__(self):
        self.models = {}
        self.encoders = {}
        self.scalers = {}
        self.vectorizers = {}
        self.threat_types = []
        self.load_models()
    
    def load_models(self):
        """Load all trained models and preprocessors"""
        if not os.path.exists('models'):
            return
        
        # Find all threat types
        model_files = [f for f in os.listdir('models') if f.endswith('_model.joblib')]
        
        for model_file in model_files:
            try:
                parts = model_file.replace('_model.joblib', '').split('_')
                algorithm = parts[-1]
                threat_type = '_'.join(parts[:-1])
                
                # Skip temporary models
                if threat_type.startswith(('fast', 'lightning')):
                    continue
                
                if threat_type not in self.threat_types:
                    self.threat_types.append(threat_type)
                
                # Load model
                model_key = f"{threat_type}_{algorithm}"
                self.models[model_key] = joblib.load(f'models/{model_file}')
                
                # Load preprocessors
                if threat_type not in self.encoders:
                    encoder_file = f'models/{threat_type}_encoder.joblib'
                    if os.path.exists(encoder_file):
                        self.encoders[threat_type] = joblib.load(encoder_file)
                    else:
                        # Try algorithm-specific encoder
                        algo_encoder_file = f'models/{threat_type}_{algorithm}_encoder.joblib'
                        if os.path.exists(algo_encoder_file):
                            self.encoders[threat_type] = joblib.load(algo_encoder_file)
                
                if threat_type not in self.scalers:
                    scaler_file = f'models/{threat_type}_scaler.joblib'
                    if os.path.exists(scaler_file):
                        self.scalers[threat_type] = joblib.load(scaler_file)
                
                # Load vectorizers (algorithm-specific for some threat types)
                vectorizer_key = f"{threat_type}_{algorithm}"
                if vectorizer_key not in self.vectorizers:
                    # Try algorithm-specific vectorizer first
                    algo_vectorizer_file = f'models/{threat_type}_{algorithm}_vectorizer.joblib'
                    if os.path.exists(algo_vectorizer_file):
                        self.vectorizers[vectorizer_key] = joblib.load(algo_vectorizer_file)
                    else:
                        # Fallback to general vectorizer
                        general_vectorizer_file = f'models/{threat_type}_vectorizer.joblib'
                        if os.path.exists(general_vectorizer_file):
                            self.vectorizers[vectorizer_key] = joblib.load(general_vectorizer_file)
                        
            except Exception as e:
                print(f"Error loading {model_file}: {e}")
        
        self.threat_types = sorted(self.threat_types)
    
    def predict_text_threat(self, threat_type, text_input):
        """Predict threat for text-based inputs"""
        try:
            available_models = [k for k in self.models.keys() if k.startswith(f"{threat_type}_")]
            
            if not available_models:
                return {"error": f"No models found for {threat_type}"}
            
            results = {}
            
            for model_key in available_models:
                algorithm = model_key.split('_')[-1]
                vectorizer_key = f"{threat_type}_{algorithm}"
                
                # Vectorize text
                if vectorizer_key in self.vectorizers:
                    X_vectorized = self.vectorizers[vectorizer_key].transform([text_input])
                    
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
        """Predict threat for numeric-based inputs"""
        try:
            available_models = [k for k in self.models.keys() if k.startswith(f"{threat_type}_")]
            
            if not available_models:
                return {"error": f"No models found for {threat_type}"}
            
            # Generate synthetic features based on description
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
        features = []
        
        # Keyword-based features
        keywords = threat_keywords.get(threat_type, [])
        for keyword in keywords[:5]:
            features.append(1.0 if keyword in desc_lower else 0.0)
        
        # Add random network-like features
        np.random.seed(hash(description) % 2**32)
        
        # Traffic volume features
        if any(word in desc_lower for word in ['high', 'flood', 'volume', 'multiple']):
            features.extend(np.random.uniform(800, 1000, 5))
        else:
            features.extend(np.random.uniform(10, 100, 5))
        
        # Timing features
        if any(word in desc_lower for word in ['slow', 'delay', 'timeout']):
            features.extend(np.random.uniform(5000, 10000, 5))
        else:
            features.extend(np.random.uniform(10, 500, 5))
        
        # Flag features
        if any(word in desc_lower for word in ['attack', 'malicious', 'suspicious']):
            features.extend(np.random.uniform(0.7, 1.0, 5))
        else:
            features.extend(np.random.uniform(0.0, 0.3, 5))
        
        return features[:20]

# Initialize the detection engine
detection_engine = ThreatDetectionEngine()

def home(request):
    """Main dashboard view"""
    context = {
        'threat_types': detection_engine.threat_types,
        'total_models': len(detection_engine.models),
        'title': 'Threat Detection System - Web Interface'
    }
    return render(request, 'home.html', context)

def analyze_threat(request):
    """Single threat analysis view"""
    # Get available models for each threat type
    threat_models = {}
    for threat_type in detection_engine.threat_types:
        models = []
        for model_key in detection_engine.models.keys():
            if model_key.startswith(f"{threat_type}_"):
                algorithm = model_key.split('_')[-1]
                models.append(algorithm.upper())
        threat_models[threat_type] = sorted(list(set(models)))
    
    context = {
        'threat_types': detection_engine.threat_types,
        'threat_models': threat_models,
        'title': 'Analyze Threat'
    }
    return render(request, 'analyze.html', context)

def batch_analysis(request):
    """Batch analysis view"""
    context = {
        'threat_types': detection_engine.threat_types,
        'title': 'Batch Analysis'
    }
    return render(request, 'batch.html', context)

def system_status(request):
    """System status and statistics view"""
    # Get model statistics
    threat_model_counts = {}
    for threat_type in detection_engine.threat_types:
        count = len([k for k in detection_engine.models.keys() if k.startswith(f"{threat_type}_")])
        threat_model_counts[threat_type] = count
    
    context = {
        'threat_types': detection_engine.threat_types,
        'threat_model_counts': threat_model_counts,
        'total_models': len(detection_engine.models),
        'has_models': len(detection_engine.models) > 0,
        'title': 'System Status'
    }
    return render(request, 'status.html', context)

@csrf_exempt
@require_http_methods(["POST"])
def api_predict(request):
    """API endpoint for threat prediction"""
    try:
        data = json.loads(request.body)
        threat_type = data.get('threat_type')
        input_text = data.get('input_text', '').strip()
        
        if not threat_type or not input_text:
            return JsonResponse({
                'error': 'Missing threat_type or input_text'
            }, status=400)
        
        if threat_type not in detection_engine.threat_types:
            return JsonResponse({
                'error': f'Unknown threat type: {threat_type}'
            }, status=400)
        
        # Determine prediction method
        text_based_threats = ['phishing']
        
        if threat_type in text_based_threats:
            results = detection_engine.predict_text_threat(threat_type, input_text)
        else:
            results = detection_engine.predict_numeric_threat(threat_type, input_text)
        
        if 'error' in results:
            return JsonResponse({
                'error': results['error']
            }, status=500)
        
        # Format results for web display
        formatted_results = []
        for algorithm, result in results.items():
            formatted_results.append({
                'algorithm': algorithm.upper(),
                'prediction': result['prediction'],
                'confidence': result.get('confidence'),
                'is_threat': result['prediction'] not in ['benign', 'legitimate']
            })
        
        return JsonResponse({
            'success': True,
            'threat_type': threat_type,
            'input_text': input_text,
            'results': formatted_results,
            'timestamp': datetime.now().isoformat()
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def api_predict_specific(request):
    """API endpoint for specific model prediction"""
    try:
        data = json.loads(request.body)
        threat_type = data.get('threat_type')
        algorithm = data.get('algorithm', '').lower()
        input_text = data.get('input_text', '').strip()
        
        if not threat_type or not algorithm or not input_text:
            return JsonResponse({
                'error': 'Missing threat_type, algorithm, or input_text'
            }, status=400)
        
        if threat_type not in detection_engine.threat_types:
            return JsonResponse({
                'error': f'Unknown threat type: {threat_type}'
            }, status=400)
        
        # Check if specific model exists
        model_key = f"{threat_type}_{algorithm}"
        if model_key not in detection_engine.models:
            return JsonResponse({
                'error': f'Model {algorithm.upper()} not available for {threat_type}'
            }, status=400)
        
        # Get single model prediction
        try:
            # Determine prediction method
            text_based_threats = ['phishing', 'brute_force', 'ddos', 'malware', 'web_attacks']
            
            if threat_type in text_based_threats:
                # Text-based prediction
                vectorizer_key = f"{threat_type}_{algorithm}"
                if vectorizer_key in detection_engine.vectorizers:
                    X_vectorized = detection_engine.vectorizers[vectorizer_key].transform([input_text])
                    
                    # Predict
                    model = detection_engine.models[model_key]
                    prediction = model.predict(X_vectorized)[0]
                    probability = model.predict_proba(X_vectorized)[0] if hasattr(model, 'predict_proba') else None
                    
                    # Decode prediction
                    if threat_type in detection_engine.encoders:
                        try:
                            prediction = detection_engine.encoders[threat_type].inverse_transform([prediction])[0]
                        except:
                            pass
                    
                    # Calculate confidence
                    confidence = max(probability) if probability is not None else None
                    
                    result = {
                        'algorithm': algorithm.upper(),
                        'prediction': str(prediction),
                        'confidence': float(confidence) if confidence else None,
                        'is_threat': str(prediction).lower() not in ['benign', 'legitimate', 'normal']
                    }
                else:
                    return JsonResponse({
                        'error': f'No vectorizer found for {threat_type} with {algorithm} algorithm'
                    }, status=500)
            else:
                # Numeric-based prediction
                try:
                    # Parse numeric input
                    features = [float(x.strip()) for x in input_text.split(',')]
                    X = np.array(features).reshape(1, -1)
                    
                    # Scale if scaler exists
                    if threat_type in detection_engine.scalers:
                        X = detection_engine.scalers[threat_type].transform(X)
                    
                    # Predict
                    model = detection_engine.models[model_key]
                    prediction = model.predict(X)[0]
                    probability = model.predict_proba(X)[0] if hasattr(model, 'predict_proba') else None
                    
                    # Decode prediction
                    if threat_type in detection_engine.encoders:
                        try:
                            prediction = detection_engine.encoders[threat_type].inverse_transform([prediction])[0]
                        except:
                            pass
                    
                    # Calculate confidence
                    confidence = max(probability) if probability is not None else None
                    
                    result = {
                        'algorithm': algorithm.upper(),
                        'prediction': str(prediction),
                        'confidence': float(confidence) if confidence else None,
                        'is_threat': str(prediction).lower() not in ['benign', 'legitimate', 'normal']
                    }
                except ValueError:
                    return JsonResponse({
                        'error': 'Invalid numeric input format. Use comma-separated values.'
                    }, status=400)
            
            return JsonResponse({
                'success': True,
                'threat_type': threat_type,
                'algorithm': algorithm.upper(),
                'input_text': input_text,
                'result': result,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            return JsonResponse({
                'error': f'Prediction failed: {str(e)}'
            }, status=500)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def api_predict_all(request):
    """API endpoint for testing against all threat types"""
    try:
        data = json.loads(request.body)
        input_text = data.get('input_text', '').strip()
        
        if not input_text:
            return JsonResponse({
                'error': 'Missing input_text'
            }, status=400)
        
        all_results = {}
        
        for threat_type in detection_engine.threat_types:
            # Determine prediction method
            text_based_threats = ['phishing']
            
            if threat_type in text_based_threats:
                results = detection_engine.predict_text_threat(threat_type, input_text)
            else:
                results = detection_engine.predict_numeric_threat(threat_type, input_text)
            
            if 'error' not in results:
                formatted_results = []
                for algorithm, result in results.items():
                    formatted_results.append({
                        'algorithm': algorithm.upper(),
                        'prediction': result['prediction'],
                        'confidence': result.get('confidence'),
                        'is_threat': result['prediction'] not in ['benign', 'legitimate']
                    })
                all_results[threat_type] = formatted_results
        
        return JsonResponse({
            'success': True,
            'input_text': input_text,
            'results': all_results,
            'timestamp': datetime.now().isoformat()
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)

def api_status(request):
    """API endpoint for system status"""
    threat_model_counts = {}
    for threat_type in detection_engine.threat_types:
        count = len([k for k in detection_engine.models.keys() if k.startswith(f"{threat_type}_")])
        threat_model_counts[threat_type] = count
    
    return JsonResponse({
        'status': 'online',
        'threat_types': detection_engine.threat_types,
        'threat_model_counts': threat_model_counts,
        'total_models': len(detection_engine.models),
        'timestamp': datetime.now().isoformat()
    })
