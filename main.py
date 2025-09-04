"""
Threat Detection System - Main Entry Point
Orchestrates the complete threat detection pipeline
"""

import argparse
import sys
import logging
from pathlib import Path
from datetime import datetime
import subprocess

# Import our modules
from preprocessing import ThreatDataPreprocessor
from train_models import ThreatDetectionTrainer
from detect import HybridThreatDetector
from config import *

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / f'threat_detection_{datetime.now().strftime("%Y%m%d")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatDetectionSystem:
    """
    Main class for orchestrating the complete threat detection system
    """
    
    def __init__(self):
        self.preprocessor = None
        self.trainer = None
        self.detector = None
        
        # Ensure all directories exist
        for directory in [PROCESSED_DATA_DIR, MODELS_DIR, LOGS_DIR, RULES_DIR]:
            directory.mkdir(exist_ok=True)
    
    def setup_environment(self):
        """Setup and verify the environment"""
        logger.info("Setting up threat detection environment...")
        
        # Check if datasets exist
        missing_datasets = []
        
        # Check individual files
        if not DATASET_PATHS['emails'].exists():
            missing_datasets.append(str(DATASET_PATHS['emails']))
        if not DATASET_PATHS['malware'].exists():
            missing_datasets.append(str(DATASET_PATHS['malware']))
        
        # Check CICIDS files
        for cicids_file in DATASET_PATHS['cicids_files']:
            if not cicids_file.exists():
                missing_datasets.append(str(cicids_file))
        
        if missing_datasets:
            logger.warning(f"Missing datasets: {missing_datasets}")
            logger.info("The system will work with available datasets only.")
        
        # Create default rules if they don't exist
        self._create_default_rules()
        
        logger.info("Environment setup completed.")
    
    def _create_default_rules(self):
        """Create default detection rules"""
        logger.info("Creating default detection rules...")
        
        # Default malware hashes (examples)
        default_hashes = [
            "d41d8cd98f00b204e9800998ecf8427e",  # Empty file hash
            "5d41402abc4b2a76b9719d911017c592",  # "hello" MD5
        ]
        
        # Default phishing domains (examples)
        default_phishing = [
            "phishing-example.com",
            "fake-bank.tk",
            "malicious-site.ml"
        ]
        
        # Default malicious IPs (examples)
        default_ips = [
            "192.0.2.1",  # Test IP
            "203.0.113.1",  # Test IP
        ]
        
        # Default attack patterns
        default_patterns = [
            "union select",
            "script>alert",
            "../etc/passwd"
        ]
        
        rules_data = {
            'malware_hashes.txt': default_hashes,
            'phishing_domains.txt': default_phishing,
            'malicious_ips.txt': default_ips,
            'attack_patterns.txt': default_patterns
        }
        
        for filename, data in rules_data.items():
            rule_path = RULES_DIR / filename
            if not rule_path.exists():
                with open(rule_path, 'w') as f:
                    f.write('\\n'.join(data))
                logger.info(f"Created default rules: {filename}")
    
    def run_preprocessing(self, force_reprocess=False):
        """Run data preprocessing pipeline"""
        logger.info("Starting data preprocessing...")
        
        # Check if processed data already exists
        unified_path = PROCESSED_DATA_DIR / "unified_dataset.csv"
        if unified_path.exists() and not force_reprocess:
            logger.info("Processed data already exists. Use --force-preprocess to reprocess.")
            return True
        
        try:
            self.preprocessor = ThreatDataPreprocessor()
            processed_datasets = self.preprocessor.process_all_datasets()
            
            if not processed_datasets:
                logger.error("No datasets were successfully processed!")
                return False
            
            unified_dataset = self.preprocessor.create_unified_dataset(processed_datasets)
            
            if unified_dataset.empty:
                logger.error("Failed to create unified dataset!")
                return False
            
            logger.info("Data preprocessing completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Error during preprocessing: {e}")
            return False
    
    def run_training(self, force_retrain=False):
        """Run model training pipeline"""
        logger.info("Starting model training...")
        
        # Check if models already exist
        model_files = list(MODELS_DIR.glob("*.joblib"))
        if model_files and not force_retrain:
            logger.info("Trained models already exist. Use --force-retrain to retrain.")
            return True
        
        # Check if processed data exists
        unified_path = PROCESSED_DATA_DIR / "unified_dataset.csv"
        if not unified_path.exists():
            logger.error("Processed data not found! Run preprocessing first.")
            return False
        
        try:
            self.trainer = ThreatDetectionTrainer()
            
            # Load processed data
            df = self.trainer.load_processed_data()
            
            # Prepare training data
            binary_data, multiclass_data = self.trainer.prepare_training_data(df)
            
            # Train all models
            results = self.trainer.train_all_models(binary_data, multiclass_data)
            
            # Save models
            self.trainer.save_models(results, binary_data['feature_names'])
            
            # Generate performance report
            self.trainer.generate_performance_report(results)
            
            # Create visualizations
            self.trainer.create_visualizations(results)
            
            if not results:
                logger.error("Model training failed!")
                return False
            
            logger.info("Model training completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Error during training: {e}")
            return False
    
    def run_detection(self, input_data=None, input_file=None):
        """Run threat detection"""
        logger.info("Starting threat detection...")
        
        try:
            self.detector = HybridThreatDetector()
            
            if input_file:
                # Process file
                results = self.detector.process_file(input_file)
                
                # Print results summary
                threats_found = sum(1 for r in results if r['final_verdict']['is_threat'])
                print(f"\\n{'='*60}")
                print(f"THREAT DETECTION RESULTS")
                print(f"{'='*60}")
                print(f"File: {input_file}")
                print(f"Total items analyzed: {len(results)}")
                print(f"Threats detected: {threats_found}")
                print(f"Detection rate: {threats_found/len(results)*100:.1f}%")
                
                # Show threat details
                if threats_found > 0:
                    print(f"\\n{'='*60}")
                    print(f"THREAT DETAILS")
                    print(f"{'='*60}")
                    
                    for i, result in enumerate(results):
                        if result['final_verdict']['is_threat']:
                            verdict = result['final_verdict']
                            print(f"\\nThreat {i+1}:")
                            print(f"  Confidence: {verdict['confidence']:.2%}")
                            print(f"  Severity: {verdict['severity']}")
                            print(f"  Types: {', '.join(verdict['threat_types'])}")
                            
                            if 'alerts' in result:
                                for alert in result['alerts']:
                                    print(f"  Alert: {alert['message']}")
                
                return results
            
            elif input_data:
                # Process single input
                result = self.detector.detect_threats(input_data)
                
                print(f"\\n{'='*60}")
                print(f"THREAT DETECTION RESULT")
                print(f"{'='*60}")
                
                verdict = result['final_verdict']
                if verdict['is_threat']:
                    print(f"🚨 THREAT DETECTED!")
                    print(f"Confidence: {verdict['confidence']:.2%}")
                    print(f"Severity: {verdict['severity']}")
                    print(f"Types: {', '.join(verdict['threat_types'])}")
                else:
                    print(f"✅ No threats detected")
                
                return [result]
            
            else:
                # Demo mode
                logger.info("Running in demo mode...")
                self.run_demo()
                return []
                
        except Exception as e:
            logger.error(f"Error during detection: {e}")
            return []
    
    def run_demo(self):
        """Run demonstration of the threat detection system"""
        print(f"\\n{'='*60}")
        print(f"THREAT DETECTION SYSTEM DEMO")
        print(f"{'='*60}")
        
        # Demo samples
        demo_samples = [
            {
                'name': 'Phishing Email',
                'data': {
                    'text': 'Urgent: Your PayPal account has been suspended. Click here to verify: http://paypal-security.tk/login',
                    'source': 'email_demo'
                }
            },
            {
                'name': 'SQL Injection',
                'data': {
                    'text': "'; DROP TABLE users; --",
                    'source': 'web_demo'
                }
            },
            {
                'name': 'Suspicious IP',
                'data': {
                    'ip': '192.168.1.100',
                    'source': 'network_demo'
                }
            }
        ]
        
        for i, sample in enumerate(demo_samples, 1):
            print(f"\\nDemo {i}: {sample['name']}")
            print("-" * 40)
            
            result = self.detector.detect_threats(sample['data'])
            verdict = result['final_verdict']
            
            if verdict['is_threat']:
                print(f"🚨 THREAT: {verdict['severity']} (Confidence: {verdict['confidence']:.2%})")
                print(f"Types: {', '.join(verdict['threat_types'])}")
            else:
                print(f"✅ BENIGN (Confidence: {verdict['confidence']:.2%})")
    
    def run_dashboard(self):
        """Launch the Streamlit dashboard"""
        logger.info("Launching threat detection dashboard...")
        
        import sys  # Move import outside try block
        
        try:
            import streamlit.web.cli as stcli
            
            # Set up the command to run streamlit
            dashboard_path = Path(__file__).parent / "visualize.py"
            sys.argv = ["streamlit", "run", str(dashboard_path)]
            
            # Run streamlit
            stcli.main()
            
        except ImportError:
            logger.error("Streamlit not available. Install with: pip install streamlit")
            
            # Fallback: run with subprocess
            try:
                dashboard_path = Path(__file__).parent / "visualize.py"
                subprocess.run([
                    sys.executable, "-m", "streamlit", "run", str(dashboard_path)
                ])
            except Exception as e:
                logger.error(f"Failed to launch dashboard: {e}")
    
    def run_full_pipeline(self, force_reprocess=False, force_retrain=False):
        """Run the complete threat detection pipeline"""
        logger.info("Starting complete threat detection pipeline...")
        
        # Step 1: Setup environment
        self.setup_environment()
        
        # Step 2: Preprocessing
        if not self.run_preprocessing(force_reprocess):
            logger.error("Pipeline failed at preprocessing stage!")
            return False
        
        # Step 3: Training
        if not self.run_training(force_retrain):
            logger.error("Pipeline failed at training stage!")
            return False
        
        # Step 4: Demo detection
        self.run_detection()
        
        logger.info("Complete pipeline executed successfully!")
        return True

def main():
    """Main entry point with command line interface"""
    parser = argparse.ArgumentParser(description="Threat Detection System")
    parser.add_argument(
        'command',
        choices=['setup', 'preprocess', 'train', 'detect', 'dashboard', 'full'],
        help='Command to execute'
    )
    
    # Preprocessing options
    parser.add_argument(
        '--force-preprocess',
        action='store_true',
        help='Force reprocessing even if processed data exists'
    )
    
    # Training options
    parser.add_argument(
        '--force-retrain',
        action='store_true',
        help='Force retraining even if models exist'
    )
    
    # Detection options
    parser.add_argument(
        '--input-file',
        type=str,
        help='File to analyze for threats'
    )
    parser.add_argument(
        '--text',
        type=str,
        help='Text to analyze for threats'
    )
    parser.add_argument(
        '--ip',
        type=str,
        help='IP address to check'
    )
    parser.add_argument(
        '--domain',
        type=str,
        help='Domain to check'
    )
    
    args = parser.parse_args()
    
    # Initialize system
    system = ThreatDetectionSystem()
    
    # Execute command
    if args.command == 'setup':
        system.setup_environment()
        print("✅ Environment setup completed!")
    
    elif args.command == 'preprocess':
        success = system.run_preprocessing(args.force_preprocess)
        if success:
            print("✅ Data preprocessing completed!")
        else:
            print("❌ Data preprocessing failed!")
            sys.exit(1)
    
    elif args.command == 'train':
        success = system.run_training(args.force_retrain)
        if success:
            print("✅ Model training completed!")
        else:
            print("❌ Model training failed!")
            sys.exit(1)
    
    elif args.command == 'detect':
        input_data = {}
        if args.text:
            input_data['text'] = args.text
        if args.ip:
            input_data['ip'] = args.ip
        if args.domain:
            input_data['domain'] = args.domain
        if not input_data and not args.input_file:
            input_data = None  # Demo mode
        
        results = system.run_detection(
            input_data=input_data if input_data else None,
            input_file=args.input_file
        )
        
        if results:
            print("✅ Threat detection completed!")
        else:
            print("❌ Threat detection failed!")
    
    elif args.command == 'dashboard':
        system.run_dashboard()
    
    elif args.command == 'full':
        success = system.run_full_pipeline(
            args.force_preprocess,
            args.force_retrain
        )
        if success:
            print("✅ Full pipeline completed successfully!")
        else:
            print("❌ Pipeline execution failed!")
            sys.exit(1)

if __name__ == "__main__":
    # If no arguments provided, show help and run full pipeline
    if len(sys.argv) == 1:
        print("🛡️ Threat Detection System")
        print("=" * 50)
        print("Running full pipeline by default...")
        print("Use 'python main.py --help' for more options.")
        print()
        
        system = ThreatDetectionSystem()
        system.run_full_pipeline()
    else:
        main()
