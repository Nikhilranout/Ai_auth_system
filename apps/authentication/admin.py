"""
Admin configuration for authentication app.
"""

from django.contrib import admin
from .models import PasswordReset, EmailVerification


@admin.register(PasswordReset)
class PasswordResetAdmin(admin.ModelAdmin):
    """Password Reset admin."""
    
    list_display = ('user', 'is_used', 'created_at', 'expires_at')
    list_filter = ('is_used', 'created_at')
    search_fields = ('user__email',)
    readonly_fields = ('token', 'created_at', 'used_at')


@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    """Email Verification admin."""
    
    list_display = ('user', 'email', 'is_verified', 'created_at', 'expires_at')
    list_filter = ('is_verified', 'created_at')
    search_fields = ('user__email', 'email')
    readonly_fields = ('token', 'created_at', 'verified_at')
