"""
Threat Detection System - Installation and Setup Script
Automated setup for the complete threat detection system
"""

import subprocess
import sys
import os
from pathlib import Path
import logging

def setup_logging():
    """Setup logging for the installer"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def check_python_version():
    """Check if Python version is compatible"""
    logger = logging.getLogger(__name__)
    
    if sys.version_info < (3, 8):
        logger.error("Python 3.8 or higher is required!")
        return False
    
    logger.info(f"Python version {sys.version} is compatible")
    return True

def install_requirements():
    """Install required Python packages"""
    logger = logging.getLogger(__name__)
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    if not requirements_file.exists():
        logger.error("requirements.txt not found!")
        return False
    
    logger.info("Installing Python packages...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
        ])
        logger.info("✅ All packages installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to install packages: {e}")
        return False

def download_nltk_data():
    """Download required NLTK data"""
    logger = logging.getLogger(__name__)
    
    logger.info("Downloading NLTK data...")
    
    try:
        import nltk
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)
        logger.info("✅ NLTK data downloaded successfully!")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to download NLTK data: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    logger = logging.getLogger(__name__)
    
    directories = [
        "processed_data",
        "models", 
        "logs",
        "rules"
    ]
    
    base_path = Path(__file__).parent
    
    for directory in directories:
        dir_path = base_path / directory
        dir_path.mkdir(exist_ok=True)
        logger.info(f"Created directory: {directory}")
    
    return True

def check_datasets():
    """Check if required datasets are available"""
    logger = logging.getLogger(__name__)
    
    dataset_dir = Path(__file__).parent / "dataset"
    
    if not dataset_dir.exists():
        logger.warning("⚠️ Dataset directory not found!")
        logger.info("Please ensure your datasets are in the 'dataset/' directory")
        return False
    
    # Check for some expected files
    expected_files = [
        "emails.csv",
        "Obfuscated-MalMem2022.csv"
    ]
    
    found_files = []
    for file in expected_files:
        if (dataset_dir / file).exists():
            found_files.append(file)
    
    logger.info(f"Found {len(found_files)} out of {len(expected_files)} expected dataset files")
    
    # List all files in dataset directory
    all_files = list(dataset_dir.glob("*"))
    logger.info(f"Total files in dataset directory: {len(all_files)}")
    
    return True

def run_initial_test():
    """Run a basic system test"""
    logger = logging.getLogger(__name__)
    
    logger.info("Running initial system test...")
    
    try:
        # Import main modules to check for errors
        from config import PROJECT_ROOT
        from preprocessing import ThreatDataPreprocessor
        from detect import HybridThreatDetector
        
        logger.info("✅ All modules imported successfully!")
        
        # Test basic initialization
        detector = HybridThreatDetector()
        test_result = detector.detect_threats({
            'text': 'test message',
            'source': 'setup_test'
        })
        
        if test_result:
            logger.info("✅ Basic detection test passed!")
            return True
        else:
            logger.warning("⚠️ Basic detection test returned no results")
            return False
            
    except Exception as e:
        logger.error(f"❌ Initial test failed: {e}")
        return False

def print_setup_summary():
    """Print setup completion summary"""
    print("\\n" + "="*60)
    print("🛡️  THREAT DETECTION SYSTEM SETUP COMPLETE")
    print("="*60)
    print()
    print("✅ Environment setup completed successfully!")
    print()
    print("📋 Next Steps:")
    print("1. Ensure your datasets are in the 'dataset/' directory")
    print("2. Run the complete pipeline:")
    print("   python main.py full")
    print()
    print("3. Or run individual components:")
    print("   python main.py preprocess    # Process datasets")
    print("   python main.py train         # Train models")
    print("   python main.py detect        # Run detection demo")
    print("   python main.py dashboard     # Launch dashboard")
    print()
    print("4. Run tests to validate:")
    print("   python test_system.py")
    print()
    print("📖 Check README.md for detailed usage instructions")
    print("="*60)

def main():
    """Main setup function"""
    print("🛡️ Threat Detection System - Setup and Installation")
    print("="*60)
    
    logger = setup_logging()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        sys.exit(1)
    
    # Download NLTK data
    if not download_nltk_data():
        sys.exit(1)
    
    # Create directories
    if not create_directories():
        sys.exit(1)
    
    # Check datasets
    check_datasets()
    
    # Run initial test
    if not run_initial_test():
        logger.warning("⚠️ Initial test had issues, but setup continues...")
    
    # Print summary
    print_setup_summary()

if __name__ == "__main__":
    main()
