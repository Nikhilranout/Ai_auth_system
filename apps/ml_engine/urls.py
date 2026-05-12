"""
URL configuration for ML engine app.
"""

from django.urls import path
from . import views

app_name = 'ml_engine'

urlpatterns = [
    path('dashboard/', views.model_dashboard, name='dashboard'),
    path('train/', views.train_model_view, name='train'),
    path('info/', views.model_info_view, name='info'),
]
