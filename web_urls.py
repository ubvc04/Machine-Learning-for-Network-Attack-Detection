"""
🌐 URL Configuration for Threat Detection Web Interface
======================================================
URL patterns for the Django web interface.
"""

from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
import web_views

urlpatterns = [
    # Main pages
    path('', web_views.home, name='home'),
    path('analyze/', web_views.analyze_threat, name='analyze'),
    path('batch/', web_views.batch_analysis, name='batch'),
    path('status/', web_views.system_status, name='status'),
    
    # API endpoints
    path('api/predict/', web_views.api_predict, name='api_predict'),
    path('api/predict-specific/', web_views.api_predict_specific, name='api_predict_specific'),
    path('api/predict-all/', web_views.api_predict_all, name='api_predict_all'),
    path('api/status/', web_views.api_status, name='api_status'),
]

# Serve static files during development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0])
