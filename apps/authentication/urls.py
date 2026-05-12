"""
URL configuration for authentication app.
"""

from django.urls import path
from . import views

app_name = 'auth'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('resend-otp/', views.resend_otp, name='resend_otp'),
    # Email verification for signup
    path('verify-email/', views.verify_otp_email, name='verify_otp_email'),
    path('resend-email-otp/', views.resend_email_otp, name='resend_email_otp'),
    # Password reset
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<str:token_id>/<str:token>/', views.reset_password, name='reset_password'),
]
