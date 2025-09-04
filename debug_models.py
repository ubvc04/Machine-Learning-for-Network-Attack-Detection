#!/usr/bin/env python3
"""
Quick debug script to test model loading
"""
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_settings')
django.setup()

try:
    import web_views
    print("=== THREAT DETECTION DEBUG ===")
    print(f"Detection engine initialized: {web_views.detection_engine is not None}")
    print(f"Threat types: {web_views.detection_engine.threat_types}")
    print(f"Total models loaded: {len(web_views.detection_engine.models)}")
    print(f"Model keys: {list(web_views.detection_engine.models.keys())[:10]}...")  # Show first 10
    
    # Test a simple prediction
    if web_views.detection_engine.threat_types:
        test_threat = web_views.detection_engine.threat_types[0]
        print(f"Testing threat type: {test_threat}")
        
    print("=== DEBUG COMPLETE ===")
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
