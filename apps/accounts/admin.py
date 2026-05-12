"""
Admin configuration for accounts app.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from .models import User, UserProfile, BehaviorLog, LoginLog, OTPVerification, TrustedDevice, SuspiciousActivity


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User admin."""
    
    list_display = ('email', 'username', 'role', 'is_active', 'email_verified', 'created_at')
    list_filter = ('role', 'is_active', 'email_verified', 'created_at')
    search_fields = ('email', 'username')
    ordering = ('-created_at',)
    
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Role & Status', {'fields': ('role', 'email_verified', 'is_account_locked')}),
        ('Security', {'fields': ('login_attempts', 'last_login_attempt')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at', 'last_login')}),
    )
    
    readonly_fields = ('created_at', 'updated_at', 'last_login')


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """User Profile admin."""
    
    list_display = ('user', 'full_name', 'phone', 'two_factor_enabled', 'created_at')
    search_fields = ('user__email', 'full_name')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(BehaviorLog)
class BehaviorLogAdmin(admin.ModelAdmin):
    """Behavior Log admin."""
    
    list_display = ('user', 'trust_score_display', 'risk_level', 'device_type', 'browser_type', 'created_at')
    list_filter = ('risk_level', 'device_type', 'browser_type', 'created_at')
    search_fields = ('user__email', 'username_attempted', 'ip_address', 'device_fingerprint')
    readonly_fields = ('trust_score_display', 'created_at', 'updated_at')
    
    fieldsets = (
        ('User Info', {'fields': ('user', 'username_attempted', 'session_id')}),
        ('Typing Biometrics', {
            'fields': (
                'typing_speed', 'key_interval', 'hold_time', 'avg_hold_time',
                'avg_flight_time', 'total_typing_time', 'pause_time',
                'hesitation_score', 'backspace_count', 'delete_count',
                'correction_ratio', 'retry_count', 'mistake_correction_pattern'
            )
        }),
        ('Mouse Biometrics', {
            'fields': (
                'mouse_speed', 'mouse_avg_speed', 'total_mouse_distance',
                'click_count', 'double_click_count', 'click_interval',
                'hover_pause', 'hover_pattern_score', 'idle_time', 'idle_ratio',
                'field_transition_time', 'submit_latency', 'scroll_pattern',
                'cursor_direction_changes'
            )
        }),
        ('Login Context', {
            'fields': (
                'login_time_hour', 'device_type', 'device', 'browser_type',
                'browser', 'browser_version', 'ip_address', 'os_type', 'platform',
                'screen_resolution', 'screen_size', 'timezone', 'language',
                'device_fingerprint', 'returning_device', 'paste_detected',
                'autofill_detected', 'suspicious_input'
            )
        }),
        ('AI Analysis', {
            'fields': ('trust_score', 'risk_level', 'prediction_label', 'anomaly_score', 'authentication_outcome', 'model_version')
        }),
    )
    
    def trust_score_display(self, obj):
        """Display trust score with color coding."""
        if obj.trust_score >= 80:
            color = 'green'
        elif obj.trust_score >= 50:
            color = 'orange'
        else:
            color = 'red'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.1f}</span>',
            color, obj.trust_score
        )
    trust_score_display.short_description = 'Trust Score'


@admin.register(LoginLog)
class LoginLogAdmin(admin.ModelAdmin):
    """Login Log admin."""
    
    list_display = ('email', 'status_display', 'ip_address', 'trust_score', 'timestamp')
    list_filter = ('status', 'risk_level', 'otp_required', 'timestamp')
    search_fields = ('email', 'ip_address', 'user__email')
    readonly_fields = ('timestamp', 'session_id')
    
    fieldsets = (
        ('User Info', {'fields': ('user', 'email')}),
        ('Device Info', {'fields': ('ip_address', 'browser', 'device', 'os')}),
        ('Login Status', {'fields': ('status', 'risk_level', 'failure_reason')}),
        ('OTP', {'fields': ('otp_required', 'otp_verified')}),
        ('AI Analysis', {'fields': ('trust_score',)}),
        ('Session', {'fields': ('session_id', 'duration', 'location')}),
        ('Timestamp', {'fields': ('timestamp',)}),
    )
    
    def status_display(self, obj):
        """Display status with color coding."""
        colors = {
            'success': 'green',
            'failed': 'red',
            'otp_required': 'orange',
            'blocked': 'darkred',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_display.short_description = 'Status'


@admin.register(OTPVerification)
class OTPVerificationAdmin(admin.ModelAdmin):
    """OTP Verification admin."""
    
    list_display = ('user', 'verification_status', 'delivery_method', 'attempts', 'created_at')
    list_filter = ('is_verified', 'delivery_method', 'created_at')
    search_fields = ('user__email', 'sent_to')
    readonly_fields = ('created_at', 'verified_at')
    
    def verification_status(self, obj):
        """Display verification status."""
        if obj.is_verified:
            return format_html(
                '<span style="color: green; font-weight: bold;">✓ Verified</span>'
            )
        elif obj.is_expired():
            return format_html(
                '<span style="color: red; font-weight: bold;">✗ Expired</span>'
            )
        else:
            return format_html(
                '<span style="color: orange; font-weight: bold;">⏳ Pending</span>'
            )
    verification_status.short_description = 'Status'


@admin.register(TrustedDevice)
class TrustedDeviceAdmin(admin.ModelAdmin):
    """Trusted Device admin."""
    
    list_display = ('device_name', 'user', 'browser', 'os', 'is_active', 'last_used')
    list_filter = ('is_active', 'browser', 'os', 'created_at')
    search_fields = ('user__email', 'device_name', 'ip_address')
    readonly_fields = ('created_at', 'last_used')


@admin.register(SuspiciousActivity)
class SuspiciousActivityAdmin(admin.ModelAdmin):
    """Suspicious Activity admin."""
    
    list_display = ('user', 'activity_type', 'severity', 'ip_address', 'is_resolved', 'created_at')
    list_filter = ('activity_type', 'severity', 'is_resolved', 'created_at')
    search_fields = ('user__email', 'ip_address', 'description')
    readonly_fields = ('created_at',)
    
    fieldsets = (
        ('Activity Info', {'fields': ('user', 'activity_type', 'severity', 'description')}),
        ('Device Info', {'fields': ('ip_address', 'device_fingerprint', 'user_agent')}),
        ('Resolution', {'fields': ('is_resolved', 'resolved_at', 'resolved_by')}),
        ('Timestamp', {'fields': ('created_at',)}),
    )
