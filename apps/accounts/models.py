"""
Models for accounts app.
Includes User, UserProfile, BehaviorLog, LoginLog, and OTPVerification models.
"""

from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from django.utils import timezone
from django.core.validators import RegexValidator
import uuid


class CustomUserManager(UserManager):
    """Custom user manager for User model."""
    
    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular user."""
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a superuser."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'admin')
        extra_fields.setdefault('email_verified', True)
        extra_fields.setdefault('is_email_verified', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        if extra_fields.get('is_active') is not True:
            raise ValueError('Superuser must have is_active=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom User model with email-based authentication."""
    
    ROLE_CHOICES = [
        ('user', 'Regular User'),
        ('admin', 'Administrator'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    is_active = models.BooleanField(default=False)  # Default inactive for email verification
    email_verified = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)  # For email OTP verification
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_attempt = models.DateTimeField(null=True, blank=True)
    login_attempts = models.IntegerField(default=0)
    is_account_locked = models.BooleanField(default=False)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def __str__(self):
        return self.email
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_active']),
        ]


class UserProfile(models.Model):
    """Extended user profile information."""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    full_name = models.CharField(max_length=255)
    phone = models.CharField(
        max_length=15,
        blank=True,
        validators=[RegexValidator(r'^\+?1?\d{9,15}$')]
    )
    profile_image = models.ImageField(
        upload_to='profiles/%Y/%m/%d/',
        blank=True,
        null=True
    )
    bio = models.TextField(blank=True)
    two_factor_enabled = models.BooleanField(default=False)
    login_notifications = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Profile of {self.user.email}"
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"


class BehaviorLog(models.Model):
    """Track user behavioral biometrics during login."""
    
    RISK_LEVEL_CHOICES = [
        ('low', 'Low Risk'),
        ('medium', 'Medium Risk'),
        ('high', 'High Risk'),
        ('critical', 'Critical Risk'),
    ]

    AUTH_OUTCOME_CHOICES = [
        ('pending', 'Pending'),
        ('success', 'Success'),
        ('otp_required', 'OTP Required'),
        ('blocked', 'Blocked'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='behavior_logs',
        null=True,
        blank=True,
    )
    session_id = models.CharField(max_length=100, blank=True)
    username_attempted = models.EmailField(blank=True)
    
    # Typing biometrics
    typing_speed = models.FloatField(default=0.0)  # Characters per second
    key_interval = models.FloatField(default=0.0)  # Average ms between key presses
    hold_time = models.FloatField(default=0.0)  # Average key hold time in ms
    avg_hold_time = models.FloatField(default=0.0)
    avg_flight_time = models.FloatField(default=0.0)
    total_typing_time = models.FloatField(default=0.0)
    pause_time = models.FloatField(default=0.0)
    hesitation_score = models.FloatField(default=0.0)
    retry_count = models.IntegerField(default=0)
    backspace_count = models.IntegerField(default=0)
    delete_count = models.IntegerField(default=0)
    correction_ratio = models.FloatField(default=0.0)
    mistake_correction_pattern = models.FloatField(default=0.0)
    
    # Mouse biometrics
    mouse_speed = models.FloatField(default=0.0)  # Pixels per second
    mouse_avg_speed = models.FloatField(default=0.0)
    total_mouse_distance = models.FloatField(default=0.0)
    click_count = models.IntegerField(default=0)
    double_click_count = models.IntegerField(default=0)
    click_interval = models.FloatField(default=0.0)  # Average time between clicks
    hover_pause = models.FloatField(default=0.0)  # Time spent hovering
    hover_pattern_score = models.FloatField(default=0.0)
    idle_time = models.FloatField(default=0.0)
    idle_ratio = models.FloatField(default=0.0)
    field_transition_time = models.FloatField(default=0.0)
    submit_latency = models.FloatField(default=0.0)
    scroll_pattern = models.FloatField(default=0.0)
    cursor_direction_changes = models.IntegerField(default=0)
    
    # Login context
    login_time_hour = models.IntegerField()  # Hour of day (0-23)
    device_type = models.CharField(max_length=50)  # Desktop, Tablet, Mobile
    device = models.CharField(max_length=50, blank=True)
    browser_type = models.CharField(max_length=50)  # Chrome, Firefox, Safari, etc.
    browser = models.CharField(max_length=50, blank=True)
    browser_version = models.CharField(max_length=50, blank=True)
    ip_address = models.GenericIPAddressField()
    os_type = models.CharField(max_length=50, blank=True)
    platform = models.CharField(max_length=50, blank=True)
    screen_resolution = models.CharField(max_length=50, blank=True)
    screen_size = models.CharField(max_length=50, blank=True)
    timezone = models.CharField(max_length=100, blank=True)
    language = models.CharField(max_length=20, blank=True)
    device_fingerprint = models.CharField(max_length=255, blank=True)
    returning_device = models.BooleanField(default=False)
    paste_detected = models.BooleanField(default=False)
    autofill_detected = models.BooleanField(default=False)
    suspicious_input = models.BooleanField(default=False)
    
    # ML prediction
    trust_score = models.FloatField(default=50.0)  # 0-100
    risk_level = models.CharField(
        max_length=20,
        choices=RISK_LEVEL_CHOICES,
        default='medium'
    )
    anomaly_score = models.FloatField(default=0.0)
    prediction_label = models.CharField(max_length=30, blank=True)
    authentication_outcome = models.CharField(
        max_length=20,
        choices=AUTH_OUTCOME_CHOICES,
        default='pending',
    )
    model_version = models.CharField(max_length=50, default='v1.0')
    
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        """Keep legacy and extended fields in sync for backward compatibility."""
        if self.avg_hold_time and not self.hold_time:
            self.hold_time = self.avg_hold_time
        elif self.hold_time and not self.avg_hold_time:
            self.avg_hold_time = self.hold_time

        if self.avg_flight_time and not self.key_interval:
            self.key_interval = self.avg_flight_time
        elif self.key_interval and not self.avg_flight_time:
            self.avg_flight_time = self.key_interval

        if self.mouse_avg_speed and not self.mouse_speed:
            self.mouse_speed = self.mouse_avg_speed
        elif self.mouse_speed and not self.mouse_avg_speed:
            self.mouse_avg_speed = self.mouse_speed

        if self.correction_ratio and not self.mistake_correction_pattern:
            self.mistake_correction_pattern = self.correction_ratio
        elif self.mistake_correction_pattern and not self.correction_ratio:
            self.correction_ratio = self.mistake_correction_pattern

        if self.browser_type and not self.browser:
            self.browser = self.browser_type
        elif self.browser and not self.browser_type:
            self.browser_type = self.browser

        if self.device_type and not self.device:
            self.device = self.device_type
        elif self.device and not self.device_type:
            self.device_type = self.device

        if self.screen_resolution and not self.screen_size:
            self.screen_size = self.screen_resolution
        elif self.screen_size and not self.screen_resolution:
            self.screen_resolution = self.screen_size

        super().save(*args, **kwargs)

    def __str__(self):
        identity = self.user.email if self.user else (self.username_attempted or 'anonymous')
        return f"Behavior Log - {identity} - Trust: {self.trust_score}"
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Behavior Log"
        verbose_name_plural = "Behavior Logs"
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['ip_address']),
        ]


class LoginLog(models.Model):
    """Log all login attempts with detailed information."""
    
    STATUS_CHOICES = [
        ('success', 'Successful'),
        ('failed', 'Failed'),
        ('otp_required', 'OTP Required'),
        ('blocked', 'Blocked'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='login_logs',
        null=True,
        blank=True
    )
    email = models.EmailField()  # Store email even if user not found
    
    ip_address = models.GenericIPAddressField()
    browser = models.CharField(max_length=100)
    device = models.CharField(max_length=100)
    os = models.CharField(max_length=100, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    risk_level = models.CharField(max_length=20, default='medium')
    trust_score = models.FloatField(null=True, blank=True)
    
    failure_reason = models.CharField(max_length=200, blank=True)
    otp_required = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)
    
    location = models.CharField(max_length=200, blank=True)  # Geolocation if available
    session_id = models.CharField(max_length=100, blank=True)
    
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    duration = models.IntegerField(default=0)  # Session duration in seconds
    
    def __str__(self):
        return f"{self.email} - {self.status} - {self.timestamp}"
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Login Log"
        verbose_name_plural = "Login Logs"
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['email']),
        ]


class OTPVerification(models.Model):
    """OTP management for suspicious login verification."""
    
    DELIVERY_METHOD_CHOICES = [
        ('email', 'Email'),
        ('sms', 'SMS'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otp_verifications')
    login_log = models.OneToOneField(
        LoginLog,
        on_delete=models.CASCADE,
        related_name='otp_verification'
    )
    
    otp_code = models.CharField(max_length=10)
    delivery_method = models.CharField(
        max_length=20,
        choices=DELIVERY_METHOD_CHOICES,
        default='email'
    )
    sent_to = models.CharField(max_length=255)  # Email or phone number
    
    is_verified = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=3)
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()  # Default 5 minutes
    verified_at = models.DateTimeField(null=True, blank=True)
    
    def is_expired(self):
        """Check if OTP is expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if OTP is still valid."""
        return not self.is_expired() and not self.is_verified and self.attempts < self.max_attempts
    
    def verify(self, code):
        """Verify OTP code."""
        if not self.is_valid():
            return False
        
        self.attempts += 1
        
        if code == self.otp_code:
            self.is_verified = True
            self.verified_at = timezone.now()
            return True
        
        self.save()
        return False
    
    def __str__(self):
        return f"OTP - {self.user.email} - {'Verified' if self.is_verified else 'Pending'}"
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "OTP Verification"
        verbose_name_plural = "OTP Verifications"
        indexes = [
            models.Index(fields=['user', '-created_at']),
        ]


class TrustedDevice(models.Model):
    """Track trusted devices to skip OTP for known devices."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='trusted_devices')
    
    device_name = models.CharField(max_length=100)
    device_fingerprint = models.CharField(max_length=255, unique=True)
    browser = models.CharField(max_length=100)
    os = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    
    is_active = models.BooleanField(default=True)
    last_used = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()  # 90 days by default
    
    def is_expired(self):
        """Check if device trust has expired."""
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"{self.device_name} - {self.user.email}"
    
    class Meta:
        ordering = ['-last_used']
        verbose_name = "Trusted Device"
        verbose_name_plural = "Trusted Devices"


class SuspiciousActivity(models.Model):
    """Track and flag suspicious login patterns."""
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    ACTIVITY_TYPE_CHOICES = [
        ('brute_force', 'Brute Force Attempt'),
        ('unusual_time', 'Unusual Login Time'),
        ('new_device', 'New Device Detected'),
        ('new_location', 'New IP/Location'),
        ('multiple_failures', 'Multiple Failed Attempts'),
        ('suspicious_behavior', 'Suspicious Behavior Pattern'),
        ('otp_brute_force', 'OTP Brute Force'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='suspicious_activities',
        null=True,
        blank=True,
    )
    activity_type = models.CharField(
        max_length=30,
        choices=ACTIVITY_TYPE_CHOICES,
        default='suspicious_behavior',
    )
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default='medium',
    )
    description = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_fingerprint = models.CharField(max_length=255, blank=True)
    user_agent = models.TextField(blank=True)
    
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_activities',
    )
    
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    def __str__(self):
        identity = self.user.email if self.user else 'Unknown'
        return f"{self.get_activity_type_display()} - {identity} - {self.severity}"
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Suspicious Activity"
        verbose_name_plural = "Suspicious Activities"
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['is_resolved']),
        ]
