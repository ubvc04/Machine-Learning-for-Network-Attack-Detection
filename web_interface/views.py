"""
Web Interface Views for Threat Detection System
Integrated into the main project directory
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import joblib
import numpy as np
from pathlib import Path
import time

# Use the models directory from the main project
MODELS_DIR = Path(__file__).resolve().parent.parent / 'models'

# Threat types configuration
THREAT_TYPES = {
    'phishing': {
        'name': 'Phishing Detection',
        'description': 'Detect phishing emails and suspicious links',
        'icon': '🎣',
        'examples': [
            'Click here to verify your paypal account',
            'Your account has been suspended, login now',
            'URGENT: Update your password or lose access'
        ]
    },
    'malware': {
        'name': 'Malware Detection', 
        'description': 'Identify malicious software and suspicious behavior',
        'icon': '🦠',
        'examples': [
            'malicious executable detected in system',
            'suspicious behavior pattern identified',
            'virus signature match found'
        ]
    },
    'ddos': {
        'name': 'DDoS Attack Detection',
        'description': 'Detect distributed denial of service attacks',
        'icon': '🌊',
        'examples': [
            'high traffic volume detected unusual',
            'multiple connection attempts same source',
            'bandwidth utilization spike abnormal'
        ]
    },
    'web_attacks': {
        'name': 'Web Attack Detection',
        'description': 'Identify SQL injection, XSS, and other web attacks',
        'icon': '🕷️',
        'examples': [
            "SELECT * FROM users WHERE password=''",
            "<script>alert('xss attack')</script>",
            "../../../etc/passwd"
        ]
    },
    'brute_force': {
        'name': 'Brute Force Detection',
        'description': 'Detect password cracking and brute force attempts',
        'icon': '🔨',
        'examples': [
            'multiple login attempts admin admin123',
            'password brute force attack detected', 
            'repeated authentication failures'
        ]
    }
}

def home(request):
    """Home page with threat type selection"""
    # Check available models
    available_models = 0
    for threat_type in THREAT_TYPES.keys():
        for model_type in ['sgd', 'nb']:
            model_file = MODELS_DIR / f"{threat_type}_{model_type}_model.joblib"
            if model_file.exists():
                available_models += 1
    
    context = {
        'threat_types': THREAT_TYPES,
        'total_models': available_models,
        'title': 'Threat Detection System'
    }
    return render(request, 'home.html', context)

def detect_threat(request, threat_type):
    """Threat detection page for specific threat type"""
    if threat_type not in THREAT_TYPES:
        return render(request, 'error.html', {'error': 'Invalid threat type'})
    
    # Check available models for this threat type
    available_models = []
    for model_type in ['sgd', 'nb']:
        model_file = MODELS_DIR / f"{threat_type}_{model_type}_model.joblib"
        if model_file.exists():
            available_models.append({
                'value': model_type,
                'name': 'SGD Classifier' if model_type == 'sgd' else 'Naive Bayes'
            })
    
    context = {
        'threat_type': threat_type,
        'threat_info': THREAT_TYPES[threat_type],
        'available_models': available_models,
        'title': f'{THREAT_TYPES[threat_type]["name"]} - Detection'
    }
    return render(request, 'detect.html', context)

@csrf_exempt
def analyze_threat(request):
    """API endpoint for threat analysis"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        threat_type = data.get('threat_type')
        input_text = data.get('input_text', '').strip()
        model_choice = data.get('model', 'nb')
        
        if not threat_type or threat_type not in THREAT_TYPES:
            return JsonResponse({'error': 'Invalid threat type'}, status=400)
        
        if not input_text:
            return JsonResponse({'error': 'Input text is required'}, status=400)
        
        # Analyze the threat
        start_time = time.time()
        result = analyze_single_threat(threat_type, input_text, model_choice)
        analysis_time = time.time() - start_time
        
        if 'error' in result:
            return JsonResponse(result, status=500)
        
        # Add timing information
        result['analysis_time'] = round(analysis_time, 3)
        result['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
        
        return JsonResponse(result)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Analysis error: {str(e)}'}, status=500)

def analyze_single_threat(threat_type, input_text, model_choice):
    """Analyze a single threat using the specified model"""
    try:
        model_key = f"{threat_type}_{model_choice}"
        
        # Check if model files exist
        model_file = MODELS_DIR / f"{model_key}_model.joblib"
        vectorizer_file = MODELS_DIR / f"{model_key}_vectorizer.joblib"
        encoder_file = MODELS_DIR / f"{model_key}_encoder.joblib"
        
        if not all([model_file.exists(), vectorizer_file.exists(), encoder_file.exists()]):
            return {'error': f'Model files not found for {threat_type} - {model_choice}'}
        
        # Load model components
        model = joblib.load(model_file)
        vectorizer = joblib.load(vectorizer_file)
        encoder = joblib.load(encoder_file)
        
        # Process input
        X = vectorizer.transform([input_text]).toarray()
        
        # Make prediction
        prediction = model.predict(X)[0]
        result = encoder.inverse_transform([prediction])[0]
        
        # Get confidence
        confidence = 0.5
        try:
            proba = model.predict_proba(X)[0]
            confidence = float(max(proba))
        except:
            pass
        
        # Determine threat level and recommendation
        if result == 'threat':
            if confidence > 0.8:
                threat_level = 'HIGH'
                color = '#ff4757'
                recommendation = f"⚠️ HIGH RISK: This appears to be a {threat_type} attack. Take immediate action!"
            elif confidence > 0.6:
                threat_level = 'MEDIUM'
                color = '#ffa502'
                recommendation = f"⚡ MEDIUM RISK: Suspicious {threat_type} pattern detected. Investigate further."
            else:
                threat_level = 'LOW'
                color = '#ff7675'
                recommendation = f"🔍 LOW RISK: Possible {threat_type} indicators. Monitor closely."
        else:
            threat_level = 'SAFE'
            color = '#00b894'
            recommendation = "✅ SAFE: No threat detected. Content appears legitimate."
        
        return {
            'success': True,
            'threat_type': threat_type,
            'result': result.upper(),
            'confidence': confidence,
            'confidence_percent': round(confidence * 100, 1),
            'threat_level': threat_level,
            'threat_level_color': color,
            'model_used': model_choice,
            'model_name': 'SGD Classifier' if model_choice == 'sgd' else 'Naive Bayes',
            'input_text': input_text,
            'is_threat': result == 'threat',
            'threat_category': THREAT_TYPES[threat_type]['name'],
            'recommendation': recommendation
        }
        
    except Exception as e:
        return {'error': f'Model analysis error: {str(e)}'}

@csrf_exempt
def bulk_analysis(request):
    """API endpoint for bulk threat analysis"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        threat_type = data.get('threat_type')
        input_list = data.get('input_list', [])
        model_choice = data.get('model', 'nb')
        
        if not threat_type or threat_type not in THREAT_TYPES:
            return JsonResponse({'error': 'Invalid threat type'}, status=400)
        
        if not input_list or not isinstance(input_list, list):
            return JsonResponse({'error': 'Input list is required'}, status=400)
        
        results = []
        threat_count = 0
        
        for i, text in enumerate(input_list):
            if text.strip():
                result = analyze_single_threat(threat_type, text.strip(), model_choice)
                if 'error' not in result:
                    result['index'] = i
                    if result['is_threat']:
                        threat_count += 1
                    results.append(result)
        
        return JsonResponse({
            'success': True,
            'total_analyzed': len(results),
            'threats_detected': threat_count,
            'threat_percentage': round((threat_count / len(results)) * 100, 1) if results else 0,
            'results': results
        })
        
    except Exception as e:
        return JsonResponse({'error': f'Bulk analysis error: {str(e)}'}, status=500)

def model_status(request):
    """API endpoint to check model availability"""
    status = {}
    total_models = 0
    
    for threat_type in THREAT_TYPES.keys():
        threat_models = {}
        for model_type in ['sgd', 'nb']:
            model_key = f"{threat_type}_{model_type}"
            model_file = MODELS_DIR / f"{model_key}_model.joblib"
            vectorizer_file = MODELS_DIR / f"{model_key}_vectorizer.joblib"
            encoder_file = MODELS_DIR / f"{model_key}_encoder.joblib"
            
            is_available = all([
                model_file.exists(),
                vectorizer_file.exists(),
                encoder_file.exists()
            ])
            
            threat_models[model_type] = {
                'available': is_available,
                'model_name': 'SGD Classifier' if model_type == 'sgd' else 'Naive Bayes',
                'files': {
                    'model': str(model_file) if model_file.exists() else None,
                    'vectorizer': str(vectorizer_file) if vectorizer_file.exists() else None,
                    'encoder': str(encoder_file) if encoder_file.exists() else None
                }
            }
            
            if is_available:
                total_models += 1
        
        status[threat_type] = {
            'name': THREAT_TYPES[threat_type]['name'],
            'icon': THREAT_TYPES[threat_type]['icon'],
            'models': threat_models
        }
    
    return JsonResponse({
        'models_directory': str(MODELS_DIR),
        'total_threat_types': len(THREAT_TYPES),
        'total_models_available': total_models,
        'threat_types': status,
        'system_status': 'operational' if total_models > 0 else 'no_models'
    })
