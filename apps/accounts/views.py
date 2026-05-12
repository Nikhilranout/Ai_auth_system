"""
Views for accounts app.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from .models import UserProfile, LoginLog
from .forms import UserRegistrationForm, UserProfileForm, PasswordChangeForm

User = get_user_model()


@require_http_methods(["GET"])
def profile_view(request):
    """View user profile."""
    if not request.user.is_authenticated:
        return redirect('auth:login')
    
    profile = UserProfile.objects.get(user=request.user)
    context = {
        'profile': profile,
    }
    return render(request, 'accounts/profile.html', context)


@require_http_methods(["GET", "POST"])
@login_required(login_url='auth:login')
@csrf_protect
def update_profile(request):
    """Update user profile."""
    profile = UserProfile.objects.get(user=request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('accounts:profile')
        else:
            messages.error(request, 'Error updating profile. Please check the form.')
    else:
        form = UserProfileForm(instance=profile)
    
    context = {
        'form': form,
        'profile': profile,
    }
    return render(request, 'accounts/edit_profile.html', context)


@require_http_methods(["GET", "POST"])
@login_required(login_url='auth:login')
@csrf_protect
def change_password(request):
    """Change user password."""
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = request.user
            user.set_password(form.cleaned_data['new_password1'])
            user.save()
            
            # Log the password change
            messages.success(request, 'Password changed successfully. Please login again.')
            logout(request)
            return redirect('auth:login')
        else:
            messages.error(request, 'Error changing password.')
    else:
        form = PasswordChangeForm(request.user)
    
    context = {'form': form}
    return render(request, 'accounts/change_password.html', context)


@require_http_methods(["GET"])
@login_required(login_url='auth:login')
def account_security(request):
    """View account security information."""
    login_history = LoginLog.objects.filter(user=request.user).order_by('-timestamp')[:10]
    trusted_devices = request.user.trusted_devices.filter(is_active=True)
    
    # Get last login
    last_login = LoginLog.objects.filter(
        user=request.user,
        status='success'
    ).order_by('-timestamp').first()
    
    context = {
        'login_history': login_history,
        'trusted_devices': trusted_devices,
        'last_login': last_login,
    }
    return render(request, 'accounts/security.html', context)


@require_http_methods(["POST"])
@login_required(login_url='auth:login')
@csrf_protect
def remove_trusted_device(request, device_id):
    """Remove a trusted device."""
    device = get_object_or_404(request.user.trusted_devices, pk=device_id)
    device.is_active = False
    device.save()
    messages.success(request, 'Device removed from trusted devices.')
    return redirect('accounts:security')


@require_http_methods(["GET"])
@login_required(login_url='auth:login')
def login_history(request):
    """View user login history."""
    limit = request.GET.get('limit', 50)
    try:
        limit = int(limit)
    except ValueError:
        limit = 50
    
    login_logs = LoginLog.objects.filter(user=request.user).order_by('-timestamp')[:limit]
    
    # Calculate statistics
    total_logins = LoginLog.objects.filter(user=request.user, status='success').count()
    failed_logins = LoginLog.objects.filter(user=request.user, status='failed').count()
    suspicious_logins = LoginLog.objects.filter(user=request.user, risk_level='high').count()
    
    # Get unique IPs
    unique_ips = LoginLog.objects.filter(user=request.user).values('ip_address').distinct().count()
    
    context = {
        'login_logs': login_logs,
        'total_logins': total_logins,
        'failed_logins': failed_logins,
        'suspicious_logins': suspicious_logins,
        'unique_ips': unique_ips,
    }
    return render(request, 'accounts/login_history.html', context)
