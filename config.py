"""
Threat Detection System Configuration
"""
import os
from pathlib import Path

# Project Structure
PROJECT_ROOT = Path(__file__).parent.absolute()
DATA_DIR = PROJECT_ROOT / "dataset"
PROCESSED_DATA_DIR = PROJECT_ROOT / "processed_data"
MODELS_DIR = PROJECT_ROOT / "models"
LOGS_DIR = PROJECT_ROOT / "logs"
RULES_DIR = PROJECT_ROOT / "rules"

# Create directories if they don't exist
for directory in [PROCESSED_DATA_DIR, MODELS_DIR, LOGS_DIR, RULES_DIR]:
    directory.mkdir(exist_ok=True)

# Dataset Paths
DATASET_PATHS = {
    'emails': DATA_DIR / 'emails.csv',
    'malware': DATA_DIR / 'Obfuscated-MalMem2022.csv',
    'ddos_balanced': DATA_DIR / 'ddos_balanced' / 'final_dataset.csv',
    'ddos_imbalanced': DATA_DIR / 'ddos_imbalanced' / 'unbalaced_20_80_dataset.csv',
    'brute_force': DATA_DIR / 'brute_force_data.json',
    'cicids_files': [
        DATA_DIR / 'Monday-WorkingHours.pcap_ISCX.csv',
        DATA_DIR / 'Tuesday-WorkingHours.pcap_ISCX.csv',
        DATA_DIR / 'Wednesday-workingHours.pcap_ISCX.csv',
        DATA_DIR / 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        DATA_DIR / 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
        DATA_DIR / 'Friday-WorkingHours-Morning.pcap_ISCX.csv',
        DATA_DIR / 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
        DATA_DIR / 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
    ]
}

# Model Configuration
MODEL_CONFIG = {
    'test_size': 0.2,
    'random_state': 42,
    'cv_folds': 5,
    'n_jobs': -1
}

# Attack Type Mappings
ATTACK_TYPES = {
    'BENIGN': 0,
    'DDoS': 1,
    'PortScan': 2,
    'Bot': 3,
    'Infiltration': 4,
    'Web Attack – Brute Force': 5,
    'Web Attack – XSS': 6,
    'Web Attack – Sql Injection': 7,
    'FTP-Patator': 8,
    'SSH-Patator': 9,
    'DoS Hulk': 10,
    'DoS GoldenEye': 11,
    'DoS slowloris': 12,
    'DoS Slowhttptest': 13,
    'Heartbleed': 14,
    'MALWARE': 15,
    'PHISHING': 16,
    'SPAM': 17
}

# Feature Engineering Settings
FEATURE_CONFIG = {
    'max_features_tfidf': 5000,
    'ngram_range': (1, 2),
    'numerical_scaler': 'standard',
    'categorical_encoding': 'label'
}

# Alert Configuration
ALERT_CONFIG = {
    'confidence_threshold': 0.1,  # Lower threshold for signature-based detection
    'log_format': '[{timestamp}] [{severity}] {attack_type} detected from {source} - Confidence: {confidence:.2f}',
    'severity_levels': {
        'LOW': 0.1,
        'MEDIUM': 0.4,
        'HIGH': 0.7,
        'CRITICAL': 0.9
    }
}

# Visualization Settings
VIZ_CONFIG = {
    'streamlit_port': 8501,
    'refresh_interval': 5,  # seconds
    'max_logs_display': 1000,
    'chart_theme': 'streamlit'
}
