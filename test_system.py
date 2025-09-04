"""
Threat Detection System - Testing and Validation Module
Comprehensive testing suite for the threat detection system
"""

import pandas as pd
import numpy as np
import json
import time
from pathlib import Path
from typing import Dict, List, Any
import logging

from main import ThreatDetectionSystem
from detect import HybridThreatDetector
from config import *

logger = logging.getLogger(__name__)

class ThreatDetectionTester:
    """
    Comprehensive testing suite for the threat detection system
    """
    
    def __init__(self):
        self.system = ThreatDetectionSystem()
        self.detector = None
        self.test_results = {}
    
    def setup_test_environment(self):
        """Setup testing environment"""
        logger.info("Setting up test environment...")
        self.system.setup_environment()
        
        # Initialize detector
        try:
            self.detector = HybridThreatDetector()
            logger.info("Threat detector initialized for testing")
        except Exception as e:
            logger.error(f"Failed to initialize detector: {e}")
            return False
        
        return True
    
    def create_test_samples(self):
        """Create comprehensive test samples"""
        return {
            'phishing_emails': [
                {
                    'text': 'URGENT: Your PayPal account will be suspended. Click here to verify: http://paypal-security.tk/verify',
                    'expected': True,
                    'description': 'PayPal phishing with urgent language'
                },
                {
                    'text': 'Dear customer, please update your Amazon account information by clicking this link: http://amazon-security.ml/update',
                    'expected': True,
                    'description': 'Amazon phishing with suspicious domain'
                },
                {
                    'text': 'Hello, this is a normal business email about our meeting tomorrow.',
                    'expected': False,
                    'description': 'Legitimate business email'
                }
            ],
            'web_attacks': [
                {
                    'text': "'; DROP TABLE users; --",
                    'expected': True,
                    'description': 'SQL injection attack'
                },
                {
                    'text': '<script>alert("XSS")</script>',
                    'expected': True,
                    'description': 'Cross-site scripting attack'
                },
                {
                    'text': '../../../../etc/passwd',
                    'expected': True,
                    'description': 'Directory traversal attack'
                },
                {
                    'text': 'SELECT * FROM products WHERE category = "electronics"',
                    'expected': False,
                    'description': 'Legitimate SQL query'
                }
            ],
            'network_data': [
                {
                    'ip': '192.168.1.100',
                    'domain': 'suspicious-domain.tk',
                    'expected': True,
                    'description': 'Suspicious domain with private IP'
                },
                {
                    'ip': '8.8.8.8',
                    'domain': 'google.com',
                    'expected': False,
                    'description': 'Legitimate Google DNS'
                }
            ],
            'malware_indicators': [
                {
                    'text': 'CreateRemoteThread LoadLibrary GetProcAddress',
                    'expected': True,
                    'description': 'Malware API calls'
                },
                {
                    'text': 'normal application functionality',
                    'expected': False,
                    'description': 'Normal application text'
                }
            ]
        }
    
    def test_signature_detection(self):
        """Test signature-based detection"""
        logger.info("Testing signature-based detection...")
        
        test_samples = self.create_test_samples()
        results = {
            'total_tests': 0,
            'correct_predictions': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'details': []
        }
        
        for category, samples in test_samples.items():
            for sample in samples:
                results['total_tests'] += 1
                
                # Prepare test data
                test_data = {'source': f'test_{category}'}
                test_data.update(sample)
                
                # Run detection
                detection_result = self.detector.detect_threats(test_data)
                predicted = detection_result['final_verdict']['is_threat']
                expected = sample['expected']
                
                # Record results
                correct = (predicted == expected)
                if correct:
                    results['correct_predictions'] += 1
                elif predicted and not expected:
                    results['false_positives'] += 1
                elif not predicted and expected:
                    results['false_negatives'] += 1
                
                results['details'].append({
                    'category': category,
                    'description': sample['description'],
                    'expected': expected,
                    'predicted': predicted,
                    'correct': correct,
                    'confidence': detection_result['final_verdict']['confidence']
                })
        
        # Calculate metrics
        accuracy = results['correct_predictions'] / results['total_tests']
        results['accuracy'] = accuracy
        
        logger.info(f"Signature detection test completed - Accuracy: {accuracy:.2%}")
        self.test_results['signature_detection'] = results
        
        return results
    
    def test_ml_detection(self):
        """Test ML-based detection with sample data"""
        logger.info("Testing ML-based detection...")
        
        # Check if processed data exists
        unified_path = PROCESSED_DATA_DIR / "unified_dataset.csv"
        if not unified_path.exists():
            logger.warning("No processed data available for ML testing")
            return None
        
        try:
            # Load a sample of processed data
            df = pd.read_csv(unified_path)
            
            # Take a random sample for testing
            test_sample = df.sample(min(100, len(df)), random_state=42)
            
            results = {
                'total_tests': len(test_sample),
                'correct_predictions': 0,
                'predictions': [],
                'ground_truth': [],
                'confidences': []
            }
            
            for idx, row in test_sample.iterrows():
                # Prepare features
                feature_cols = [col for col in df.columns if col not in ['attack_type', 'dataset_source', 'label']]
                features = row[feature_cols].to_dict()
                
                # Run detection
                test_data = {'features': features, 'source': 'ml_test'}
                detection_result = self.detector.detect_threats(test_data)
                
                # Get predictions
                predicted = 1 if detection_result['final_verdict']['is_threat'] else 0
                expected = 1 if row['attack_type'] > 0 else 0
                
                results['predictions'].append(predicted)
                results['ground_truth'].append(expected)
                results['confidences'].append(detection_result['final_verdict']['confidence'])
                
                if predicted == expected:
                    results['correct_predictions'] += 1
            
            # Calculate metrics
            accuracy = results['correct_predictions'] / results['total_tests']
            results['accuracy'] = accuracy
            
            # Calculate additional metrics
            tp = sum(1 for p, g in zip(results['predictions'], results['ground_truth']) if p == 1 and g == 1)
            fp = sum(1 for p, g in zip(results['predictions'], results['ground_truth']) if p == 1 and g == 0)
            fn = sum(1 for p, g in zip(results['predictions'], results['ground_truth']) if p == 0 and g == 1)
            tn = sum(1 for p, g in zip(results['predictions'], results['ground_truth']) if p == 0 and g == 0)
            
            results['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0
            results['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0
            results['f1_score'] = 2 * (results['precision'] * results['recall']) / (results['precision'] + results['recall']) if (results['precision'] + results['recall']) > 0 else 0
            
            logger.info(f"ML detection test completed - Accuracy: {accuracy:.2%}")
            self.test_results['ml_detection'] = results
            
            return results
            
        except Exception as e:
            logger.error(f"Error testing ML detection: {e}")
            return None
    
    def test_performance(self):
        """Test system performance and speed"""
        logger.info("Testing system performance...")
        
        # Test detection speed
        test_samples = [
            {'text': 'test email content', 'source': 'performance_test'},
            {'ip': '192.168.1.1', 'source': 'performance_test'},
            {'text': '<script>alert("test")</script>', 'source': 'performance_test'}
        ]
        
        times = []
        for sample in test_samples:
            start_time = time.time()
            self.detector.detect_threats(sample)
            end_time = time.time()
            times.append(end_time - start_time)
        
        results = {
            'avg_detection_time': np.mean(times),
            'min_detection_time': np.min(times),
            'max_detection_time': np.max(times),
            'total_samples': len(test_samples)
        }
        
        logger.info(f"Performance test completed - Avg time: {results['avg_detection_time']:.3f}s")
        self.test_results['performance'] = results
        
        return results
    
    def test_file_processing(self):
        """Test file processing capabilities"""
        logger.info("Testing file processing...")
        
        # Create a test CSV file
        test_data = pd.DataFrame({
            'text_column': [
                'normal email content',
                'URGENT: Click here to verify your account',
                '<script>alert("xss")</script>',
                'regular business communication'
            ],
            'numeric_feature1': [1, 2, 3, 4],
            'numeric_feature2': [0.1, 0.2, 0.3, 0.4]
        })
        
        test_file_path = PROCESSED_DATA_DIR / 'test_file.csv'
        test_data.to_csv(test_file_path, index=False)
        
        try:
            # Process the test file
            results = self.detector.process_file(str(test_file_path))
            
            file_results = {
                'total_items': len(results),
                'threats_detected': sum(1 for r in results if r['final_verdict']['is_threat']),
                'processing_successful': True
            }
            
            logger.info(f"File processing test completed - {file_results['threats_detected']}/{file_results['total_items']} threats detected")
            self.test_results['file_processing'] = file_results
            
            # Clean up test file
            test_file_path.unlink(missing_ok=True)
            
            return file_results
            
        except Exception as e:
            logger.error(f"Error testing file processing: {e}")
            return {'processing_successful': False, 'error': str(e)}
    
    def run_comprehensive_tests(self):
        """Run all tests and generate a comprehensive report"""
        logger.info("Running comprehensive threat detection tests...")
        
        # Setup test environment
        if not self.setup_test_environment():
            logger.error("Failed to setup test environment")
            return False
        
        # Run all tests
        test_functions = [
            self.test_signature_detection,
            self.test_ml_detection,
            self.test_performance,
            self.test_file_processing
        ]
        
        for test_func in test_functions:
            try:
                test_func()
            except Exception as e:
                logger.error(f"Error running {test_func.__name__}: {e}")
        
        # Generate test report
        self.generate_test_report()
        
        return True
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        logger.info("Generating test report...")
        
        report = {
            'test_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'test_summary': {},
            'detailed_results': self.test_results
        }
        
        # Calculate overall summary
        total_tests = 0
        total_correct = 0
        
        for test_name, results in self.test_results.items():
            if isinstance(results, dict) and 'total_tests' in results:
                total_tests += results['total_tests']
                total_correct += results.get('correct_predictions', 0)
        
        if total_tests > 0:
            overall_accuracy = total_correct / total_tests
            report['test_summary']['overall_accuracy'] = overall_accuracy
            report['test_summary']['total_tests'] = total_tests
            report['test_summary']['total_correct'] = total_correct
        
        # Save report
        report_path = LOGS_DIR / f"test_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\\n" + "="*60)
        print("THREAT DETECTION SYSTEM TEST REPORT")
        print("="*60)
        
        for test_name, results in self.test_results.items():
            print(f"\\n{test_name.upper().replace('_', ' ')}:")
            
            if test_name == 'signature_detection':
                print(f"  Total Tests: {results['total_tests']}")
                print(f"  Accuracy: {results['accuracy']:.2%}")
                print(f"  False Positives: {results['false_positives']}")
                print(f"  False Negatives: {results['false_negatives']}")
            
            elif test_name == 'ml_detection' and results:
                print(f"  Total Tests: {results['total_tests']}")
                print(f"  Accuracy: {results['accuracy']:.2%}")
                print(f"  Precision: {results['precision']:.2%}")
                print(f"  Recall: {results['recall']:.2%}")
                print(f"  F1 Score: {results['f1_score']:.2%}")
            
            elif test_name == 'performance':
                print(f"  Average Detection Time: {results['avg_detection_time']:.3f}s")
                print(f"  Min Detection Time: {results['min_detection_time']:.3f}s")
                print(f"  Max Detection Time: {results['max_detection_time']:.3f}s")
            
            elif test_name == 'file_processing':
                print(f"  Processing Successful: {results['processing_successful']}")
                if 'total_items' in results:
                    print(f"  Items Processed: {results['total_items']}")
                    print(f"  Threats Detected: {results['threats_detected']}")
        
        if 'overall_accuracy' in report['test_summary']:
            print(f"\\nOVERALL ACCURACY: {report['test_summary']['overall_accuracy']:.2%}")
        
        print(f"\\nTest report saved to: {report_path}")
        
        return report

def main():
    """Main testing function"""
    tester = ThreatDetectionTester()
    success = tester.run_comprehensive_tests()
    
    if success:
        print("\\n✅ All tests completed successfully!")
    else:
        print("\\n❌ Some tests failed!")

if __name__ == "__main__":
    main()
