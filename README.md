# 🛡️ Machine Learning for Network Attack Detection

A comprehensive threat detection system built with Python that uses machine learning to identify and classify various types of network attacks and security threats.

## 🌟 Features

- **39 Trained ML Models** across 11 different threat categories
- **4 Machine Learning Algorithms**: Logistic Regression, Naive Bayes, SGD, Random Forest
- **Web Interface** built with Django for easy interaction
- **Real-time Analysis** with confidence scores
- **Batch Processing** capabilities for multiple threat analysis
- **RESTful API** endpoints for integration

## 🎯 Supported Threat Types

| Threat Category | Description | Data Type | Models |
|----------------|-------------|-----------|--------|
| **Bot Attacks** | Automated malicious bot activities | Network Features | LR, NB, SGD, RF |
| **Brute Force** | Password and authentication attacks | Text/Logs | LR, NB, SGD |
| **DDoS** | Distributed Denial of Service attacks | Mixed | LR, NB, SGD, RF |
| **DoS Attacks** | Denial of Service attacks | Network Features | LR, NB, SGD, RF |
| **Infiltration** | Network infiltration attempts | Network Features | LR, NB, SGD, RF |
| **Malware** | Malicious software detection | Text/Binary | LR, NB, SGD |
| **Network Baseline** | Normal network behavior | Network Features | LR, NB, SGD, RF |
| **Phishing** | Email and web phishing attacks | Text | LR, NB, SGD |
| **Port Scan** | Network port scanning activities | Network Features | LR, NB, SGD, RF |
| **Web Attacks** | SQL Injection, XSS, etc. | Text/HTTP | LR, NB, SGD |
| **DDoS Friday** | Specialized Friday traffic DDoS | Network Features | LR, NB, SGD, RF |

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Virtual environment (recommended)
- Required datasets (included in `dataset/` folder)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/ubvc04/Machine-Learning-for-Network-Attack-Detection.git
cd Machine-Learning-for-Network-Attack-Detection
```

2. **Create and activate virtual environment**
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Train models (if needed)**
```bash
python train_models.py
```

5. **Start the web interface**
```bash
python manage.py runserver
```

6. **Open your browser**
```
http://127.0.0.1:8000
```

## 📊 Project Structure

```
├── dataset/                 # Training datasets
│   ├── brute_force_data.json
│   ├── emails.csv
│   ├── *.pcap_ISCX.csv     # Network traffic data
│   └── ddos_balanced/
├── models/                  # Trained ML models
│   ├── *_lr_model.joblib    # Logistic Regression models
│   ├── *_nb_model.joblib    # Naive Bayes models
│   ├── *_sgd_model.joblib   # SGD models
│   ├── *_rf_model.joblib    # Random Forest models
│   ├── *_encoder.joblib     # Label encoders
│   ├── *_scaler.joblib      # Feature scalers
│   └── *_vectorizer.joblib  # Text vectorizers
├── templates/               # Django web templates
│   ├── base.html
│   ├── home.html
│   ├── analyze.html
│   ├── status.html
│   └── batch.html
├── static/                  # CSS, JS, images
├── logs/                    # Application logs
├── processed_data/          # Processed datasets
├── rules/                   # Detection rules
├── web_views.py            # Django views and ML engine
├── config.py               # Configuration settings
├── train_models.py         # Model training scripts
├── detect.py               # Detection utilities
└── manage.py               # Django management
```

## 🔧 Usage

### Web Interface

1. **Dashboard**: Overview of all threat types and system status
2. **Analyze**: Select threat type and algorithm for analysis
3. **Batch**: Process multiple threats simultaneously
4. **Status**: Monitor system health and model performance

### API Endpoints

- `GET /` - Main dashboard
- `GET /analyze/` - Analysis interface
- `POST /api/analyze/` - Threat analysis endpoint
- `GET /status/` - System status
- `GET /batch/` - Batch processing interface

### Example API Usage

```python
import requests

# Analyze a potential threat
response = requests.post('http://127.0.0.1:8000/api/analyze/', {
    'threat_type': 'phishing',
    'algorithm': 'lr',
    'input_text': 'Click here to verify your account immediately!'
})

result = response.json()
print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']}")
```

## 🎯 Model Performance

Our system achieves high accuracy across different threat types:

- **Text-based threats** (Phishing, Web Attacks): 85-95% accuracy
- **Network-based threats** (DDoS, Port Scan): 90-98% accuracy
- **Behavioral threats** (Bot Attacks, Infiltration): 80-92% accuracy

## 📈 Training Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `train_models.py` | Train all models | `python train_models.py` |
| `fast_train.py` | Quick training for testing | `python fast_train.py` |
| `comprehensive_train.py` | Full training with validation | `python comprehensive_train.py` |
| `lightning_train.py` | PyTorch Lightning training | `python lightning_train.py` |
| `ultra_fast_train.py` | Minimal training for demo | `python ultra_fast_train.py` |

## 🛠️ Configuration

Edit `config.py` to customize:

- Model parameters
- Training settings
- Data preprocessing options
- Web interface settings

## 📝 Datasets

The system uses various datasets for training:

- **CICIDS-2017**: Network traffic data for intrusion detection
- **Phishing emails**: Text-based phishing detection
- **Malware samples**: Binary and behavioral analysis
- **Custom datasets**: Brute force logs and web attack patterns

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CICIDS-2017 Dataset** for network traffic data
- **Django Framework** for web interface
- **Scikit-learn** for machine learning algorithms
- **Bootstrap** for responsive UI design

## 📞 Contact

- **GitHub**: [@ubvc04](https://github.com/ubvc04)
- **Project**: [Machine-Learning-for-Network-Attack-Detection](https://github.com/ubvc04/Machine-Learning-for-Network-Attack-Detection)

## 🏆 System Highlights

- ✅ **39 Models Trained** across 11 threat categories
- ✅ **Multiple Algorithms** for comprehensive detection
- ✅ **Web Interface** for easy interaction
- ✅ **API Support** for integration
- ✅ **Real-time Analysis** with confidence scoring
- ✅ **Batch Processing** for high-volume analysis
- ✅ **Comprehensive Logging** for monitoring
- ✅ **Scalable Architecture** for production use

---

*Built with ❤️ for cybersecurity and machine learning enthusiasts*
