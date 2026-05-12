"""
URL configuration for admin panel app.
"""

from django.urls import path
from . import views

app_name = 'adminpanel'

urlpatterns = [
    path('', views.admin_dashboard, name='dashboard'),
    path('users/', views.user_management, name='users'),
    path('security-logs/', views.security_logs, name='security_logs'),
    path('devices/', views.device_tracking, name='devices'),
    path('toggle-user/', views.toggle_user_status, name='toggle_user'),
    path('unlock-user/', views.unlock_user_account, name='unlock_user'),
]
