"""
URL configuration for reports app.
"""

from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('user/', views.user_report, name='user_report'),
    path('system/', views.system_report, name='system_report'),
    path('behavior/', views.behavior_report, name='behavior_report'),
]
