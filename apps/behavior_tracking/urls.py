"""
URL configuration for behavior tracking app.
"""

from django.urls import path
from . import views

app_name = 'behavior_tracking'

urlpatterns = [
    path('track/', views.track_behavior, name='track'),
    path('track-login-behavior/', views.track_behavior, name='track_login_behavior'),
]
