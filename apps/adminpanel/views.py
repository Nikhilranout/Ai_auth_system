"""
Views for admin panel app.
"""

from django.shortcuts import render
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from apps.accounts.models import User, LoginLog, BehaviorLog, SuspiciousActivity
from apps.authentication.models import PasswordReset, EmailVerification
from apps.ml_engine.models import ModelMetrics
from django.db.models import Avg, Count, Q
from datetime import timedelta
from django.utils import timezone
import json


@staff_member_required
@require_http_methods(["GET"])
def admin_dashboard(request):
    """Admin dashboard."""
    
    # User statistics
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    locked_users = User.objects.filter(is_account_locked=True).count()
    admin_users = User.objects.filter(role='admin').count()
    
    # Login statistics
    total_logins = LoginLog.objects.count()
    successful_logins = LoginLog.objects.filter(status='success').count()
    failed_logins = LoginLog.objects.filter(status='failed').count()
    otp_logins = LoginLog.objects.filter(otp_required=True).count()
    
    # Success rate
    success_rate = (successful_logins / total_logins * 100) if total_logins > 0 else 0
    
    # Suspicious activity
    suspicious_logins = LoginLog.objects.filter(
        risk_level__in=['high', 'critical']
    ).count()
    total_tracked_logins = BehaviorLog.objects.count()
    avg_typing_speed = BehaviorLog.objects.aggregate(avg=Avg('typing_speed'))['avg'] or 0
    avg_mouse_speed = BehaviorLog.objects.aggregate(avg=Avg('mouse_avg_speed'))['avg'] or 0
    failed_matches = BehaviorLog.objects.filter(authentication_outcome='blocked').count()
    
    # Today's activity
    today = timezone.now().date()
    today_logins = LoginLog.objects.filter(timestamp__date=today).count()
    today_failed = LoginLog.objects.filter(
        timestamp__date=today,
        status='failed'
    ).count()
    
    # ML model info
    latest_model = ModelMetrics.objects.filter(is_active=True).first()
    
    # Recent security events
    recent_events = LoginLog.objects.filter(
        Q(status='failed') | Q(risk_level__in=['high', 'critical'])
    ).order_by('-timestamp')[:10]
    
    # Most common IPs
    top_ips = LoginLog.objects.values('ip_address').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    risk_trends = list(
        BehaviorLog.objects.values('created_at__date', 'risk_level').annotate(
            count=Count('id')
        ).order_by('created_at__date')
    )
    device_history = BehaviorLog.objects.values('device').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Suspicious activities
    suspicious_activities = SuspiciousActivity.objects.filter(
        is_resolved=False
    ).order_by('-created_at')[:10]
    total_suspicious = SuspiciousActivity.objects.filter(is_resolved=False).count()
    
    # Daily login activity (last 14 days)
    fourteen_days_ago = timezone.now() - timedelta(days=14)
    daily_logins = LoginLog.objects.filter(
        timestamp__gte=fourteen_days_ago
    ).extra({'date': "date(timestamp)"}).values('date').annotate(
        total=Count('id'),
        success=Count('id', filter=Q(status='success')),
        failed=Count('id', filter=Q(status='failed')),
    ).order_by('date')
    
    # Auth status distribution for pie chart
    auth_stats = LoginLog.objects.values('status').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Risk level distribution for doughnut
    risk_distribution = BehaviorLog.objects.values('risk_level').annotate(
        count=Count('id')
    ).order_by('risk_level')
    
    context = {
        'total_users': total_users,
        'active_users': active_users,
        'locked_users': locked_users,
        'admin_users': admin_users,
        'total_logins': total_logins,
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'otp_logins': otp_logins,
        'success_rate': success_rate,
        'suspicious_logins': suspicious_logins,
        'total_tracked_logins': total_tracked_logins,
        'avg_typing_speed': avg_typing_speed,
        'avg_mouse_speed': avg_mouse_speed,
        'failed_matches': failed_matches,
        'today_logins': today_logins,
        'today_failed': today_failed,
        'latest_model': latest_model,
        'recent_events': recent_events,
        'top_ips': top_ips,
        'risk_trends': risk_trends,
        'device_history': device_history,
        'suspicious_activities': suspicious_activities,
        'total_suspicious': total_suspicious,
        'daily_logins': list(daily_logins),
        'auth_stats': list(auth_stats),
        'risk_distribution': list(risk_distribution),
    }
    
    return render(request, 'adminpanel/dashboard.html', context)


@staff_member_required
@require_http_methods(["GET"])
def user_management(request):
    """User management page."""
    
    search_query = request.GET.get('q', '')
    status_filter = request.GET.get('status', '')
    
    users = User.objects.all()
    
    if search_query:
        users = users.filter(
            Q(email__icontains=search_query) | Q(username__icontains=search_query)
        )
    
    if status_filter == 'active':
        users = users.filter(is_active=True, is_account_locked=False)
    elif status_filter == 'locked':
        users = users.filter(is_account_locked=True)
    elif status_filter == 'inactive':
        users = users.filter(is_active=False)
    
    context = {
        'users': users.order_by('-created_at'),
        'search_query': search_query,
        'status_filter': status_filter,
    }
    
    return render(request, 'adminpanel/user_management.html', context)


@staff_member_required
@require_http_methods(["GET"])
def security_logs(request):
    """Security logs page."""
    
    log_type = request.GET.get('type', 'all')
    days = int(request.GET.get('days', 7))
    
    since = timezone.now() - timedelta(days=days)
    
    logs = LoginLog.objects.filter(timestamp__gte=since)
    
    if log_type == 'failed':
        logs = logs.filter(status='failed')
    elif log_type == 'suspicious':
        logs = logs.filter(risk_level__in=['high', 'critical'])
    elif log_type == 'otp':
        logs = logs.filter(otp_required=True)
    
    context = {
        'logs': logs.order_by('-timestamp'),
        'log_type': log_type,
        'days': days,
    }
    
    return render(request, 'adminpanel/security_logs.html', context)


@staff_member_required
@require_http_methods(["GET"])
def device_tracking(request):
    """Device tracking page."""
    
    # Get device statistics
    device_stats = LoginLog.objects.values('device').annotate(
        count=Count('id')
    ).order_by('-count')
    
    browser_stats = LoginLog.objects.values('browser').annotate(
        count=Count('id')
    ).order_by('-count')
    
    os_stats = LoginLog.objects.values('os').annotate(
        count=Count('id')
    ).order_by('-count')
    
    context = {
        'device_stats': device_stats,
        'browser_stats': browser_stats,
        'os_stats': os_stats,
    }
    
    return render(request, 'adminpanel/device_tracking.html', context)


@staff_member_required
@require_http_methods(["POST"])
def toggle_user_status(request):
    """Toggle user active status."""
    
    try:
        user_id = request.POST.get('user_id')
        user = User.objects.get(id=user_id)
        user.is_active = not user.is_active
        user.save()
        return JsonResponse({'success': True, 'is_active': user.is_active})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@staff_member_required
@require_http_methods(["POST"])
def unlock_user_account(request):
    """Unlock user account."""
    
    try:
        user_id = request.POST.get('user_id')
        user = User.objects.get(id=user_id)
        user.is_account_locked = False
        user.login_attempts = 0
        user.save()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)
