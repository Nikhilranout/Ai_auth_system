"""
URL configuration for accounts app.
"""

from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('profile/', views.profile_view, name='profile'),
    path('profile/edit/', views.update_profile, name='edit_profile'),
    path('password/change/', views.change_password, name='change_password'),
    path('security/', views.account_security, name='security'),
    path('device/<str:device_id>/remove/', views.remove_trusted_device, name='remove_device'),
    path('login-history/', views.login_history, name='login_history'),
]
