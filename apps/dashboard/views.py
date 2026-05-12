"""
Views for dashboard app.
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from apps.accounts.models import LoginLog, TrustedDevice, BehaviorLog
from django.utils import timezone
from datetime import timedelta
from security.anomaly import get_user_behavior_baseline


@login_required(login_url='auth:login')
@require_http_methods(["GET"])
def dashboard_home(request):
    """User dashboard home page."""
    
    # Get last login
    last_login = LoginLog.objects.filter(
        user=request.user,
        status='success'
    ).order_by('-timestamp').first()
    
    # Get today's logins
    today = timezone.now().date()
    today_logins = LoginLog.objects.filter(
        user=request.user,
        status='success',
        timestamp__date=today
    ).count()
    
    # Get failed logins today
    failed_logins = LoginLog.objects.filter(
        user=request.user,
        status='failed',
        timestamp__date=today
    ).count()
    
    # Get average trust score
    recent_behaviors = BehaviorLog.objects.filter(
        user=request.user
    ).order_by('-created_at')[:10]
    latest_behavior = recent_behaviors[0] if recent_behaviors else None
    
    if recent_behaviors:
        avg_trust_score = sum(b.trust_score for b in recent_behaviors) / len(recent_behaviors)
    else:
        avg_trust_score = 0

    last_secure_login = LoginLog.objects.filter(
        user=request.user,
        status='success',
        trust_score__gte=80,
    ).order_by('-timestamp').first()

    baseline = get_user_behavior_baseline(request.user)
    login_pattern_summary = {
        'common_hour': baseline.get('common_login_hour'),
        'common_device': baseline.get('common_device') or 'Learning',
        'avg_typing_speed': baseline.get('avg_typing_speed', 0.0),
    }
    
    # Get trusted devices
    trusted_devices = TrustedDevice.objects.filter(
        user=request.user,
        is_active=True
    ).count()
    
    # Get recent login history
    recent_logins = LoginLog.objects.filter(
        user=request.user
    ).order_by('-timestamp')[:10]
    
    # Get login statistics
    total_logins = LoginLog.objects.filter(user=request.user, status='success').count()
    suspicious_logins = LoginLog.objects.filter(
        user=request.user,
        risk_level__in=['high', 'critical']
    ).count()
    
    context = {
        'last_login': last_login,
        'today_logins': today_logins,
        'failed_logins': failed_logins,
        'avg_trust_score': avg_trust_score,
        'trusted_devices': trusted_devices,
        'recent_logins': recent_logins,
        'total_logins': total_logins,
        'suspicious_logins': suspicious_logins,
        'latest_behavior': latest_behavior,
        'last_secure_login': last_secure_login,
        'recognized_device': latest_behavior.returning_device if latest_behavior else False,
        'last_trust_score': latest_behavior.trust_score if latest_behavior else 0,
        'login_pattern_summary': login_pattern_summary,
    }
    
    return render(request, 'dashboard/home.html', context)


@login_required(login_url='auth:login')
@require_http_methods(["GET"])
def dashboard_security(request):
    """Security overview."""
    
    # Login statistics
    total_logins = LoginLog.objects.filter(user=request.user).count()
    successful_logins = LoginLog.objects.filter(user=request.user, status='success').count()
    failed_logins = LoginLog.objects.filter(user=request.user, status='failed').count()
    otp_logins = LoginLog.objects.filter(user=request.user, otp_required=True).count()
    
    # Device information
    unique_devices = LoginLog.objects.filter(user=request.user).values('device').distinct().count()
    unique_browsers = LoginLog.objects.filter(user=request.user).values('browser').distinct().count()
    unique_ips = LoginLog.objects.filter(user=request.user).values('ip_address').distinct().count()
    
    # Recent suspicious activity
    suspicious_login_list = LoginLog.objects.filter(
        user=request.user,
        risk_level__in=['high', 'critical']
    ).order_by('-timestamp')[:5]
    
    # Trusted devices
    trusted_devices = TrustedDevice.objects.filter(user=request.user).order_by('-last_used')
    
    context = {
        'total_logins': total_logins,
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'otp_logins': otp_logins,
        'unique_devices': unique_devices,
        'unique_browsers': unique_browsers,
        'unique_ips': unique_ips,
        'suspicious_logins': suspicious_login_list.count(),
        'suspicious_login_list': suspicious_login_list,
        'trusted_devices': trusted_devices,
    }
    
    return render(request, 'dashboard/security.html', context)


@login_required(login_url='auth:login')
@require_http_methods(["GET"])
def behavior_analytics(request):
    """Behavior analytics page."""
    
    # Get recent behavior logs
    behavior_logs = BehaviorLog.objects.filter(user=request.user).order_by('-created_at')[:30]
    
    # Calculate statistics
    avg_typing_speed = 0
    avg_mouse_speed = 0
    avg_trust_score = 0
    avg_hold_time = 0
    avg_flight_time = 0
    suspicious_attempts = 0
    
    if behavior_logs:
        avg_typing_speed = sum(b.typing_speed for b in behavior_logs) / len(behavior_logs)
        avg_mouse_speed = sum((b.mouse_avg_speed or b.mouse_speed) for b in behavior_logs) / len(behavior_logs)
        avg_trust_score = sum(b.trust_score for b in behavior_logs) / len(behavior_logs)
        avg_hold_time = sum((b.avg_hold_time or b.hold_time) for b in behavior_logs) / len(behavior_logs)
        avg_flight_time = sum((b.avg_flight_time or b.key_interval) for b in behavior_logs) / len(behavior_logs)
        suspicious_attempts = len([b for b in behavior_logs if b.risk_level in ['high', 'critical']])
    
    # Risk level distribution
    risk_counts = {}
    for log in behavior_logs:
        risk_counts[log.risk_level] = risk_counts.get(log.risk_level, 0) + 1

    device_history = {}
    for log in behavior_logs:
        device_name = log.device or log.device_type
        device_history[device_name] = device_history.get(device_name, 0) + 1
    
    # Trust score data for chart (last 10 entries, oldest first for line chart)
    behavior_logs_trust = [
        {'time': b.created_at.strftime('%H:%M'), 'score': b.trust_score}
        for b in reversed(behavior_logs[:10])
    ]

    context = {
        'behavior_logs': behavior_logs,
        'avg_typing_speed': avg_typing_speed,
        'avg_mouse_speed': avg_mouse_speed,
        'avg_trust_score': avg_trust_score,
        'risk_counts': risk_counts,
        'avg_hold_time': avg_hold_time,
        'avg_flight_time': avg_flight_time,
        'suspicious_attempts': suspicious_attempts,
        'device_history': device_history,
        'behavior_logs_trust': behavior_logs_trust,
    }
    
    return render(request, 'dashboard/analytics.html', context)
