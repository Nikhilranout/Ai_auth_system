"""
URL configuration for dashboard app.
"""

from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard_home, name='home'),
    path('security/', views.dashboard_security, name='security'),
    path('analytics/', views.behavior_analytics, name='analytics'),
]
