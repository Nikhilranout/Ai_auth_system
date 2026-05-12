"""
Models for authentication app.
"""

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
import uuid
import secrets

User = get_user_model()


class PasswordReset(models.Model):
    """Password reset token model."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_resets')
    token = models.CharField(max_length=255, unique=True, db_index=True)
    
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()  # Default 24 hours
    used_at = models.DateTimeField(null=True, blank=True)
    
    def is_expired(self):
        """Check if token is expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if token is valid."""
        return not self.is_used and not self.is_expired()
    
    @staticmethod
    def generate_token():
        """Generate a secure token."""
        return secrets.token_urlsafe(32)
    
    def __str__(self):
        return f"Reset for {self.user.email}"
    
    class Meta:
        verbose_name = "Password Reset"
        verbose_name_plural = "Password Resets"
        ordering = ['-created_at']


class EmailVerification(models.Model):
    """Email verification token model."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_verifications')
    token = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField()
    
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()  # Default 48 hours
    verified_at = models.DateTimeField(null=True, blank=True)
    
    def is_expired(self):
        """Check if token is expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if token is valid."""
        return not self.is_verified and not self.is_expired()
    
    @staticmethod
    def generate_token():
        """Generate a secure token."""
        return secrets.token_urlsafe(32)
    
    def __str__(self):
        return f"Verification for {self.email}"
    
    class Meta:
        verbose_name = "Email Verification"
        verbose_name_plural = "Email Verifications"
        ordering = ['-created_at']
