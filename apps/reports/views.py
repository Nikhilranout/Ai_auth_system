"""
Views for reports app.
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods
from apps.accounts.models import LoginLog, BehaviorLog, User
from django.utils import timezone
from django.db import models
from datetime import timedelta
import csv
import json


@login_required(login_url='auth:login')
@require_http_methods(["GET"])
def user_report(request):
    """Generate user activity report."""

    days = int(request.GET.get('days', 30))
    export = request.GET.get('export', '')
    selected_user = request.GET.get('user_id', '')

    since = timezone.now() - timedelta(days=days)

    # Get all users for the filter dropdown (admin only)
    users = []
    if request.user.is_staff:
        users = User.objects.all().order_by('email')

    # Get login data for current user (or selected user if admin)
    target_user = request.user
    if selected_user and request.user.is_staff:
        target_user = User.objects.filter(id=selected_user).first() or request.user

    logins = LoginLog.objects.filter(
        user=target_user,
        timestamp__gte=since
    ).order_by('-timestamp')

    # Calculate statistics
    total_logins = logins.count()
    successful = logins.filter(status='success').count()
    failed = logins.filter(status='failed').count()
    suspicious = logins.filter(risk_level__in=['high', 'critical']).count()

    # Export as CSV
    if export == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="login_report.csv"'

        writer = csv.writer(response)
        writer.writerow(['Date', 'Status', 'IP Address', 'Device', 'Browser', 'Risk Level', 'Trust Score'])

        for log in logins:
            writer.writerow([
                log.timestamp,
                log.status,
                log.ip_address,
                log.device,
                log.browser,
                log.risk_level,
                log.trust_score or 'N/A'
            ])

        return response

    success_rate = (successful / total_logins * 100) if total_logins > 0 else 0
    avg_trust_score = 0
    unique_devices = 0
    if logins:
        trust_scores = [l.trust_score for l in logins if l.trust_score]
        if trust_scores:
            avg_trust_score = sum(trust_scores) / len(trust_scores)
        unique_devices = logins.values('device').distinct().count()

    report_data = {
        'total_logins': total_logins,
        'successful': successful,
        'failed': failed,
        'suspicious': suspicious,
        'success_rate': success_rate,
        'avg_trust_score': avg_trust_score,
        'unique_devices': unique_devices,
    } if total_logins > 0 else None

    context = {
        'logins': logins[:50],
        'users': users,
        'selected_user': selected_user,
        'report_data': report_data,
        'days': days,
    }

    return render(request, 'reports/user_report.html', context)


@staff_member_required
@require_http_methods(["GET"])
def system_report(request):
    """Generate system-wide report."""
    
    days = int(request.GET.get('days', 30))
    export = request.GET.get('export', '')
    
    since = timezone.now() - timedelta(days=days)
    
    # Get system data
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    
    logins = LoginLog.objects.filter(timestamp__gte=since)
    total_logins = logins.count()
    successful = logins.filter(status='success').count()
    failed = logins.filter(status='failed').count()
    suspicious = logins.filter(risk_level__in=['high', 'critical']).count()
    
    # Device statistics
    devices = {}
    for log in logins:
        key = f"{log.device} / {log.browser}"
        devices[key] = devices.get(key, 0) + 1
    
    # Export as CSV
    if export == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="system_report.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Total Users', total_users])
        writer.writerow(['Active Users', active_users])
        writer.writerow(['Total Logins', total_logins])
        writer.writerow(['Successful Logins', successful])
        writer.writerow(['Failed Logins', failed])
        writer.writerow(['Suspicious Logins', suspicious])
        writer.writerow(['Success Rate', f"{(successful/total_logins*100):.1f}%" if total_logins > 0 else "N/A"])
        
        return response
    
    success_rate = (successful / total_logins * 100) if total_logins > 0 else 0
    locked_accounts = User.objects.filter(is_account_locked=True).count()
    admin_users = User.objects.filter(is_staff=True).count()

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'total_logins': total_logins,
        'successful': successful,
        'failed': failed,
        'suspicious': suspicious,
        'success_rate': success_rate,
        'locked_accounts': locked_accounts,
        'admin_users': admin_users,
        'devices': devices,
        'auth_stats_data': {
            'successful': successful,
            'failed': failed,
            'suspicious': suspicious,
        },
        'days': days,
    }
    
    return render(request, 'reports/system_report.html', context)


@staff_member_required
@require_http_methods(["GET"])
def behavior_report(request):
    """Generate behavior analysis report."""
    
    days = int(request.GET.get('days', 30))
    
    since = timezone.now() - timedelta(days=days)
    
    behaviors = BehaviorLog.objects.filter(
        created_at__gte=since
    ).order_by('-created_at')
    
    # Calculate statistics
    avg_typing_speed = 0
    avg_mouse_speed = 0
    avg_trust_score = 0
    
    if behaviors:
        avg_typing_speed = sum(b.typing_speed for b in behaviors) / behaviors.count()
        avg_mouse_speed = sum((b.mouse_avg_speed or b.mouse_speed) for b in behaviors) / behaviors.count()
        avg_trust_score = sum(b.trust_score for b in behaviors) / behaviors.count()
    
    # Risk distribution
    risk_dist = behaviors.values('risk_level').annotate(
        count=models.Count('id')
    )
    
    context = {
        'behaviors': behaviors[:50],
        'avg_typing_speed': avg_typing_speed,
        'avg_mouse_speed': avg_mouse_speed,
        'avg_trust_score': avg_trust_score,
        'risk_dist': risk_dist,
        'days': days,
    }
    
    return render(request, 'reports/behavior_report.html', context)
