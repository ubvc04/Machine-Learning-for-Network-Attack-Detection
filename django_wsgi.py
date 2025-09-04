"""
🌐 WSGI Configuration for Threat Detection Web Interface
=======================================================
WSGI config for the threat detection system Django application.
"""

import os
import sys
from pathlib import Path
from django.core.wsgi import get_wsgi_application

# Add current directory to Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_settings')

application = get_wsgi_application()
