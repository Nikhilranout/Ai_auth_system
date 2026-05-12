"""
Views for authentication app.
"""
from typing import cast
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from django.conf import settings
from django.urls import reverse
from django.http import JsonResponse
from datetime import timedelta
from apps.accounts.models import User, LoginLog, OTPVerification, BehaviorLog, UserProfile, TrustedDevice, SuspiciousActivity
from apps.accounts.forms import UserRegistrationForm
from .models import PasswordReset
from .forms import LoginForm, OTPForm, ForgotPasswordForm, ResetPasswordForm
from security.utils import derive_device_fingerprint, parse_behavior_payload, safe_json_loads
import secrets
import json
import logging


logger = logging.getLogger(__name__)


def predict_trust_score(behavior_log):
    """Load the ML predictor lazily so missing ML deps do not break server startup."""
    from apps.ml_engine.predict import predict_trust_score as ml_predict_trust_score

    return ml_predict_trust_score(behavior_log)


def get_client_info(request):
    """Extract client information from request."""
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    ip_address = get_client_ip(request)
    
    # Simple browser and device detection
    browser = 'Unknown'
    device = 'Unknown'
    os = 'Unknown'
    
    if 'Chrome' in user_agent:
        browser = 'Chrome'
    elif 'Firefox' in user_agent:
        browser = 'Firefox'
    elif 'Safari' in user_agent:
        browser = 'Safari'
    elif 'Edge' in user_agent:
        browser = 'Edge'
    
    if 'Mobile' in user_agent:
        device = 'Mobile'
    elif 'Tablet' in user_agent:
        device = 'Tablet'
    else:
        device = 'Desktop'
    
    if 'Windows' in user_agent:
        os = 'Windows'
    elif 'Mac' in user_agent:
        os = 'Mac'
    elif 'Linux' in user_agent:
        os = 'Linux'
    elif 'Android' in user_agent:
        os = 'Android'
    elif 'iPhone' in user_agent:
        os = 'iOS'
    
    return {
        'ip_address': ip_address,
        'browser': browser,
        'device': device,
        'os': os,
        'user_agent': user_agent
    }


def remember_trusted_device(user, behavior_log, client_info):
    """Create or refresh a trusted device after a verified successful login."""
    fingerprint = behavior_log.device_fingerprint or derive_device_fingerprint(
        user.email,
        client_info['browser'],
        client_info['device'],
        client_info['os'],
        behavior_log.screen_size,
        behavior_log.timezone,
        behavior_log.language,
    )

    expires_at = timezone.now() + timedelta(days=90)
    TrustedDevice.objects.update_or_create(
        device_fingerprint=fingerprint,
        defaults={
            'user': user,
            'device_name': f"{behavior_log.device or client_info['device']} / {behavior_log.browser or client_info['browser']}",
            'browser': behavior_log.browser or client_info['browser'],
            'os': behavior_log.os_type or client_info['os'],
            'ip_address': client_info['ip_address'],
            'is_active': True,
            'expires_at': expires_at,
        },
    )


def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '').strip()
    return ip or '127.0.0.1'


def get_float_value(data, key, default=0.0):
    """Safely extract a float value from behavior data."""
    try:
        return float(data.get(key, default))
    except (TypeError, ValueError):
        return default


def get_int_value(data, key, default=0):
    """Safely extract an integer value from behavior data."""
    try:
        return int(data.get(key, default))
    except (TypeError, ValueError):
        return default


def create_email_verification_otp(request, user):
    """
    Create an email-verification OTP that is compatible with the current
    OTPVerification schema, which requires a related LoginLog.
    """
    client_info = get_client_info(request)
    stale_otps = OTPVerification.objects.filter(user=user, is_verified=False)
    stale_otp_ids = list(stale_otps.values_list('id', flat=True))

    otp_code = str(secrets.randbelow(1000000)).zfill(6)
    expires_at = timezone.now() + timedelta(minutes=settings.OTP_VALIDITY_TIME)

    login_log = LoginLog.objects.create(
        user=user,
        email=user.email,
        ip_address=client_info['ip_address'],
        browser=client_info['browser'],
        device=client_info['device'],
        os=client_info['os'],
        status='otp_required',
        risk_level='low',
        trust_score=100.0,
        otp_required=True,
        failure_reason='Email verification pending',
    )
    otp = OTPVerification.objects.create(
        user=user,
        login_log=login_log,
        otp_code=otp_code,
        delivery_method='email',
        sent_to=user.email,
        expires_at=expires_at,
    )

    try:
        send_otp_email(user.email, otp_code)
    except Exception:
        otp.delete()
        login_log.delete()
        raise

    if stale_otp_ids:
        OTPVerification.objects.filter(id__in=stale_otp_ids).delete()

    return otp


@require_http_methods(["GET", "POST"])
@csrf_protect
def register(request):
    """User registration view."""
    
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False 
            user.save()
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.full_name = form.cleaned_data.get('full_name', profile.full_name or '')
            profile.save()

            if not OTPVerification.objects.filter(user=user, is_verified=False).exists():
                try:
                    create_email_verification_otp(request, user)
                except Exception:
                    messages.warning(
                        request,
                        'Registration succeeded, but we could not send the verification code yet. '
                        'Please use resend on the verification screen.'
                    )
            
            # Store user ID in session for OTP verification
            request.session['verification_user_id'] = str(user.id)
            
            # OTP will be auto-generated by signal
            messages.success(
                request,
                'Registration successful! Please check your email for the verification code.'
            )
            return redirect('auth:verify_otp_email')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserRegistrationForm()
    
    context = {'form': form}
    return render(request, 'authentication/register.html', context)


def check_ip_rate_limit(ip_address):
    """Check if an IP address has exceeded the login rate limit."""
    window_start = timezone.now() - timedelta(seconds=settings.IP_RATE_LIMIT_WINDOW)
    attempts = LoginLog.objects.filter(
        ip_address=ip_address,
        timestamp__gte=window_start
    ).count()
    return attempts >= settings.IP_RATE_LIMIT


def record_suspicious_activity(user, activity_type, severity, description, ip_address='', device_fingerprint=''):
    """Record a suspicious activity event."""
    SuspiciousActivity.objects.create(
        user=user,
        activity_type=activity_type,
        severity=severity,
        description=description,
        ip_address=ip_address or '0.0.0.0',
        device_fingerprint=device_fingerprint,
    )


@require_http_methods(["GET", "POST"])
@csrf_protect
def login_view(request):
    """User login view with behavioral biometrics."""
    

    client_ip = get_client_ip(request)
    if check_ip_rate_limit(client_ip):
        record_suspicious_activity(
            user=None,
            activity_type='brute_force',
            severity='high',
            description=f'IP rate limit exceeded: {client_ip}',
            ip_address=client_ip,
        )
        messages.error(request, 'Too many login attempts from your IP. Please try again later.')
        return render(request, 'authentication/login.html', {'form': LoginForm()})
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')
            remember_me = form.cleaned_data.get('remember_me', False)
            
            # Look up the user record and authenticate credentials separately.
            user = User.objects.filter(email=email).first()
            authenticated_user = authenticate(
                request,
                email=email,
                password=password,
            )
            
            # Authenticate user
            if authenticated_user is not None and user is not None:
                user = cast(User, authenticated_user)
                # Check if account is active
                if not user.is_active and not (user.is_staff or user.is_superuser):
                    # Check if email is not verified - redirect to verification
                    if not user.is_email_verified:
                        request.session['verification_user_id'] = str(user.id)
                        messages.warning(request, 'Please verify your email first.')
                        return redirect('auth:verify_otp_email')
                    messages.error(request, 'Your account has been deactivated.')
                    return render(request, 'authentication/login.html', {'form': form})
                
                # Check if account is locked
                if user.is_account_locked:
                    messages.error(request, 'Your account is locked. Try again later.')
                    return render(request, 'authentication/login.html', {'form': form})
                
                # Additional check for email verification status
                # Skip email verification for staff/superuser accounts - they can login without verification
                if not user.is_email_verified and not user.is_staff and not user.is_superuser:
                    request.session['verification_user_id'] = str(user.id)
                    messages.warning(request, 'Please verify your email first.')
                    return redirect('auth:verify_otp_email')
                
                # Get behavioral data from request with error handling
                behavior_payload = safe_json_loads(request.POST.get('behavior_data'))
                if not behavior_payload and request.session.get('prefetched_behavior_data'):
                    behavior_payload = request.session.pop('prefetched_behavior_data', {})
                behavior_data = parse_behavior_payload(behavior_payload)
                
                # Get client info
                client_info = get_client_info(request)
                session_key = request.session.session_key or request.session.create() or request.session.session_key
                fingerprint = behavior_data['device_fingerprint'] or derive_device_fingerprint(
                    client_info['user_agent'],
                    behavior_data['screen_size'],
                    behavior_data['timezone'],
                    behavior_data['language'],
                    behavior_data['platform'],
                )
                behavior_data['device_fingerprint'] = fingerprint
                known_device = TrustedDevice.objects.filter(
                    user=user,
                    device_fingerprint=fingerprint,
                    is_active=True,
                ).exists()
                
                # Create behavior log with legacy and extended feature fields.
                behavior_log = BehaviorLog.objects.create(
                    user=user,
                    session_id=behavior_data['session_id'] or session_key,
                    username_attempted=email,
                    typing_speed=behavior_data['typing_speed'],
                    key_interval=behavior_data['avg_flight_time'],
                    hold_time=behavior_data['avg_hold_time'],
                    avg_hold_time=behavior_data['avg_hold_time'],
                    avg_flight_time=behavior_data['avg_flight_time'],
                    total_typing_time=behavior_data['total_typing_time'],
                    pause_time=behavior_data['pause_time'],
                    hesitation_score=behavior_data['hesitation_score'],
                    retry_count=behavior_data['retry_count'],
                    backspace_count=behavior_data['backspace_count'],
                    delete_count=behavior_data['delete_count'],
                    correction_ratio=behavior_data['correction_ratio'],
                    mistake_correction_pattern=behavior_data['correction_ratio'],
                    mouse_speed=behavior_data['mouse_avg_speed'],
                    mouse_avg_speed=behavior_data['mouse_avg_speed'],
                    total_mouse_distance=behavior_data['total_mouse_distance'],
                    click_count=behavior_data['click_count'],
                    double_click_count=behavior_data['double_click_count'],
                    click_interval=behavior_data['click_rate'],
                    hover_pause=behavior_data['hover_duration'],
                    hover_pattern_score=behavior_data['hover_pattern_score'],
                    idle_time=behavior_data['idle_time'],
                    idle_ratio=behavior_data['idle_ratio'],
                    field_transition_time=behavior_data['field_transition_time'],
                    submit_latency=behavior_data['submit_latency'],
                    cursor_direction_changes=behavior_data['direction_changes'],
                    login_time_hour=timezone.now().hour,
                    device_type=client_info['device'],
                    device=behavior_data['device'] or client_info['device'],
                    browser_type=client_info['browser'],
                    browser=behavior_data['browser'] or client_info['browser'],
                    browser_version=behavior_data['browser_version'],
                    os_type=client_info['os'],
                    platform=behavior_data['platform'],
                    ip_address=client_info['ip_address'],
                    screen_resolution=behavior_data['screen_size'],
                    screen_size=behavior_data['screen_size'],
                    timezone=behavior_data['timezone'],
                    language=behavior_data['language'],
                    device_fingerprint=fingerprint,
                    returning_device=known_device or behavior_data['returning_device'],
                    paste_detected=behavior_data['paste_detected'],
                    autofill_detected=behavior_data['autofill_detected'],
                    suspicious_input=behavior_data['suspicious_input'],
                )
                
                # Predict trust score
                try:
                    prediction = predict_trust_score(behavior_log)
                    behavior_log.trust_score = prediction['trust_score']
                    behavior_log.risk_level = prediction['risk_level']
                    behavior_log.prediction_label = prediction['prediction_label']
                    behavior_log.anomaly_score = prediction['anomaly_score']
                    behavior_log.save()
                except Exception:
                    logger.exception('Trust score prediction failed. Falling back to baseline scoring.')
                    behavior_log.trust_score = 50.0
                    behavior_log.risk_level = 'medium'
                    behavior_log.prediction_label = 'OTP Verification Required'
                    behavior_log.anomaly_score = 25.0
                    behavior_log.save()
                
                trust_safe = getattr(settings, 'TRUST_SCORE_SAFE', 75)
                trust_suspicious = getattr(settings, 'TRUST_SCORE_SUSPICIOUS', 45)
                blocked_attempt = behavior_log.trust_score < trust_suspicious
                needs_otp = trust_suspicious <= behavior_log.trust_score < trust_safe
                
                # Create login log
                login_log = LoginLog.objects.create(
                    user=user,
                    email=email,
                    ip_address=client_info['ip_address'],
                    browser=client_info['browser'],
                    device=client_info['device'],
                    os=client_info['os'],
                    status='blocked' if blocked_attempt else ('otp_required' if needs_otp else 'success'),
                    risk_level=behavior_log.risk_level,
                    trust_score=behavior_log.trust_score,
                    otp_required=needs_otp,
                    session_id=behavior_log.session_id,
                    failure_reason='Behavioral biometrics blocked the login' if blocked_attempt else '',
                )
                
                # Reset login attempts on successful password match
                user.login_attempts = 0
                user.is_account_locked = False
                user.save()
                
                if blocked_attempt:
                    behavior_log.authentication_outcome = 'blocked'
                    behavior_log.save(update_fields=['authentication_outcome', 'updated_at'])
                    messages.error(
                        request,
                        'This login was blocked because the behavior pattern was too different from the established profile.'
                    )
                    return render(request, 'authentication/login.html', {'form': form})

                if needs_otp:
                    # Generate and send OTP
                    otp_code = secrets.randbelow(1000000)
                    otp_code_str = str(otp_code).zfill(6)
                    
                    expires_at = timezone.now() + timedelta(
                        minutes=getattr(settings, 'OTP_VALIDITY_TIME', 5)
                    )
                    OTPVerification.objects.create(
                        user=user,
                        login_log=login_log,
                        otp_code=otp_code_str,
                        delivery_method='email',
                        sent_to=email,
                        expires_at=expires_at,
                    )
                    
                    # Send OTP email
                    send_otp_email(email, otp_code_str)
                    
                    # Store session data for OTP verification
                    request.session['otp_user_id'] = str(user.id)
                    request.session['otp_login_log_id'] = str(login_log.id)
                    request.session['otp_behavior_log_id'] = str(behavior_log.id)
                    behavior_log.authentication_outcome = 'otp_required'
                    behavior_log.save(update_fields=['authentication_outcome', 'updated_at'])
                    
                    messages.warning(
                        request,
                        'Additional verification is required. A one-time code has been sent to your email address.'
                    )
                    return redirect('auth:verify_otp')
                else:
                    # Direct login
                    login(request, authenticated_user)
                    user.last_login_attempt = timezone.now()
                    user.save()
                    behavior_log.authentication_outcome = 'success'
                    behavior_log.save(update_fields=['authentication_outcome', 'updated_at'])
                    remember_trusted_device(user, behavior_log, client_info)
                    
                    if remember_me:
                        request.session.set_expiry(timedelta(days=30))
                    
                    messages.success(request, f'Welcome back, {user.email}!')
                    return redirect('dashboard:home')
            else:
                # Invalid credentials
                if user:
                    user.login_attempts += 1
                    user.last_login_attempt = timezone.now()
                    
                    if user.login_attempts >= getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5):
                        user.is_account_locked = True
                    
                    user.save()
                    
                    # Log failed attempt
                    client_info = get_client_info(request)
                    LoginLog.objects.create(
                        email=email,
                        ip_address=client_info['ip_address'],
                        browser=client_info['browser'],
                        device=client_info['device'],
                        os=client_info['os'],
                        status='failed',
                        failure_reason='Invalid password',
                    )
                    
                    # Record suspicious activity if user has multiple failures
                    if user.login_attempts >= 3:
                        record_suspicious_activity(
                            user=user,
                            activity_type='multiple_failures',
                            severity='medium',
                            description=f'{user.login_attempts} failed login attempts for {email}',
                            ip_address=client_info['ip_address'],
                        )
                
                messages.error(request, 'Invalid email or password.')
        else:
            messages.error(request, 'Please fill in all fields correctly.')
    else:
        form = LoginForm()
    
    context = {'form': form}
    return render(request, 'authentication/login.html', context)


@require_http_methods(["GET", "POST"])
@csrf_protect
def verify_otp(request):
    """OTP verification view."""
    
    otp_user_id = request.session.get('otp_user_id')
    otp_login_log_id = request.session.get('otp_login_log_id')
    
    if not otp_user_id or not otp_login_log_id:
        messages.error(request, 'Invalid OTP verification session.')
        return redirect('auth:login')
    
    try:
        user = User.objects.get(id=otp_user_id)
        login_log = LoginLog.objects.get(id=otp_login_log_id)
        otp_verification = OTPVerification.objects.get(login_log=login_log)
    except (User.DoesNotExist, LoginLog.DoesNotExist, OTPVerification.DoesNotExist):
        messages.error(request, 'OTP session expired.')
        return redirect('auth:login')

    behavior_log = None
    behavior_log_id = request.session.get('otp_behavior_log_id')
    if behavior_log_id:
        behavior_log = BehaviorLog.objects.filter(id=behavior_log_id).first()
    
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data.get('otp_code')
            
            if otp_verification.is_expired():
                messages.error(request, 'OTP has expired. Please login again.')
                return redirect('auth:login')
            
            if otp_verification.verify(otp_code):
                # OTP verified
                login_log.status = 'success'
                login_log.otp_verified = True
                otp_verification.save()
                login_log.save()
                
                login(request, user)
                user.last_login_attempt = timezone.now()
                user.login_attempts = 0
                user.save()

                if behavior_log:
                    behavior_log.authentication_outcome = 'success'
                    behavior_log.save(update_fields=['authentication_outcome', 'updated_at'])
                    remember_trusted_device(user, behavior_log, get_client_info(request))
                
                # Clear session
                del request.session['otp_user_id']
                del request.session['otp_login_log_id']
                if request.session.get('otp_behavior_log_id'):
                    del request.session['otp_behavior_log_id']
                
                messages.success(request, 'Login successful!')
                return redirect('dashboard:home')
            else:
                if otp_verification.attempts >= otp_verification.max_attempts:
                    messages.error(request, 'Maximum OTP attempts exceeded. Please login again.')
                    login_log.status = 'blocked'
                    login_log.save()
                    if behavior_log:
                        behavior_log.authentication_outcome = 'blocked'
                        behavior_log.save(update_fields=['authentication_outcome', 'updated_at'])
                    return redirect('auth:login')
                else:
                    remaining = otp_verification.max_attempts - otp_verification.attempts
                    messages.error(request, f'Invalid OTP. {remaining} attempts remaining.')
        else:
            messages.error(request, 'Please enter a valid OTP.')
    else:
        form = OTPForm()
    
    context = {
        'form': form,
        'email': otp_verification.sent_to,
        'otp_object': otp_verification,
        'expiry_seconds': max(
            0,
            int((otp_verification.expires_at - timezone.now()).total_seconds())
        ) if otp_verification.expires_at else getattr(settings, 'OTP_VALIDITY_TIME', 5) * 60,
        'verify_action_url': 'auth:verify_otp',
        'resend_action_url': 'auth:resend_otp',
        'otp_title': 'Login Verification',
        'otp_heading': 'Verify Login',
        'otp_message': 'We sent a login verification code to',
        'otp_button_label': 'Verify Login',
    }
    return render(request, 'authentication/verify_otp.html', context)


@require_http_methods(["POST"])
@csrf_protect
def resend_otp(request):
    """Resend OTP."""
    
    otp_login_log_id = request.session.get('otp_login_log_id')
    if not otp_login_log_id:
        messages.error(request, 'Invalid request.')
        return redirect('auth:login')
    
    try:
        login_log = LoginLog.objects.get(id=otp_login_log_id)
        otp_verification = OTPVerification.objects.get(login_log=login_log)
    except (LoginLog.DoesNotExist, OTPVerification.DoesNotExist):
        messages.error(request, 'OTP not found.')
        return redirect('auth:login')
    
    if otp_verification.is_expired():
        messages.error(request, 'OTP session has expired.')
        return redirect('auth:login')
    
    # Generate new OTP
    otp_code = secrets.randbelow(1000000)
    otp_code_str = str(otp_code).zfill(6)
    otp_verification.otp_code = otp_code_str
    otp_verification.expires_at = timezone.now() + timedelta(
        minutes=getattr(settings, 'OTP_VALIDITY_TIME', 5)
    )
    otp_verification.save()
    
    send_otp_email(otp_verification.sent_to, otp_code_str)
    
    messages.success(request, 'OTP has been resent.')
    return redirect('auth:verify_otp')


@require_http_methods(["POST"])
def logout_view(request):
    """User logout view."""
    
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('home')


@require_http_methods(["GET", "POST"])
@csrf_protect
def forgot_password(request):
    """Forgot password view."""
    
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            user = User.objects.get(email=email)
            
            # Create password reset token
            token = PasswordReset.generate_token()
            expires_at = timezone.now() + timedelta(hours=24)
            
            password_reset = PasswordReset.objects.create(
                user=user,
                token=token,
                expires_at=expires_at
            )
            
            # Send reset email
            reset_url = request.build_absolute_uri(
                reverse('auth:reset_password', args=[password_reset.id, token])
            )
            send_password_reset_email(email, reset_url)
            
            messages.success(
                request,
                'Password reset link has been sent to your email. '
                'Please check your inbox.'
            )
            return redirect('auth:login')
    else:
        form = ForgotPasswordForm()
    
    context = {'form': form}
    return render(request, 'authentication/forgot_password.html', context)


@require_http_methods(["GET", "POST"])
@csrf_protect
def reset_password(request, token_id, token):
    """Reset password view."""
    
    try:
        password_reset = PasswordReset.objects.get(id=token_id, token=token)
    except PasswordReset.DoesNotExist:
        messages.error(request, 'Invalid reset link.')
        return redirect('auth:login')
    
    if not password_reset.is_valid():
        messages.error(request, 'Reset link has expired.')
        return redirect('auth:forgot_password')
    
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            user = password_reset.user
            user.set_password(form.cleaned_data['password1'])
            user.save()
            
            password_reset.is_used = True
            password_reset.used_at = timezone.now()
            password_reset.save()
            
            messages.success(request, 'Password has been reset. Please login with your new password.')
            return redirect('auth:login')
    else:
        form = ResetPasswordForm()
    
    context = {'form': form}
    return render(request, 'authentication/reset_password.html', context)


def send_otp_email(email, otp_code):
    """Send OTP via email using professional HTML template."""
    subject = 'AI Auth System - OTP Verification'

    # Render HTML email
    html_message = render_to_string('accounts/email/otp_email.html', {
        'user': {'email': email},
        'otp': otp_code,
        'expiry_minutes': getattr(settings, 'OTP_VALIDITY_TIME', 5),
    })
    plain_message = strip_tags(html_message)

    send_mail(
        subject,
        plain_message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        html_message=html_message,
        fail_silently=False,
    )


def send_password_reset_email(email, reset_url):
    """Send password reset link via email using HTML template."""
    subject = 'AI Auth System - Password Reset'

    html_message = render_to_string('accounts/email/password_reset_email.html', {
        'user': {'email': email},
        'reset_url': reset_url,
    })
    plain_message = strip_tags(html_message)

    send_mail(
        subject,
        plain_message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        html_message=html_message,
        fail_silently=False,
    )


# ======== NEW EMAIL VERIFICATION VIEWS FOR SIGNUP FLOW ========

@require_http_methods(["GET", "POST"])
@csrf_protect
def verify_otp_email(request):
    """
    OTP verification view for email verification during signup.
    This is separate from the login OTP verification.
    """
    user_id = request.session.get('verification_user_id')
    if not user_id:
        messages.error(request, 'No pending verification. Please register first.')
        return redirect('auth:register')
    
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data.get('otp_code')
            
            # Find the latest unverified OTP for this user
            try:
                user = User.objects.get(id=user_id)
                otp = OTPVerification.objects.filter(
                    user=user,
                    is_verified=False
                ).order_by('-created_at').first()
                
                if not otp:
                    messages.error(request, 'No pending OTP found. Please register again.')
                    return redirect('auth:register')
                
                if otp.is_expired():
                    messages.error(request, 'OTP has expired. Please request a new one.')
                    return render(request, 'authentication/verify_otp.html', {
                        'form': form,
                        'email': user.email,
                        'otp_expired': True
                    })
                
                # Verify OTP
                if otp.verify(otp_code):
                    # Activate user
                    user.is_active = True
                    user.is_email_verified = True
                    user.email_verified = True
                    user.save()
                    
                    # Mark OTP as verified
                    otp.is_verified = True
                    otp.verified_at = timezone.now()
                    otp.save()
                    
                    # Clear session
                    if request.session.get('verification_user_id'):
                        del request.session['verification_user_id']
                    
                    messages.success(request, 'Email verified successfully! You can now login.')
                    return redirect('auth:login')
                else:
                    if otp.attempts >= otp.max_attempts:
                        messages.error(request, 'Maximum attempts exceeded. Please register again.')
                        return redirect('auth:register')
                    else:
                        remaining = otp.max_attempts - otp.attempts
                        messages.error(request, f'Invalid OTP. {remaining} attempts remaining.')
            except User.DoesNotExist:
                messages.error(request, 'User not found. Please register again.')
                return redirect('auth:register')
        else:
            messages.error(request, 'Please enter a valid OTP.')
    else:
        form = OTPForm()
    
    # Get user for display
    try:
        user = User.objects.get(id=user_id)
        email = user.email
        otp = OTPVerification.objects.filter(
            user=user,
            is_verified=False
        ).order_by('-created_at').first()
        
        if otp and otp.expires_at:
            # Calculate remaining time
            remaining = otp.expires_at - timezone.now()
            expiry_seconds = max(0, int(remaining.total_seconds()))
        else:
            expiry_seconds = getattr(settings, 'OTP_VALIDITY_TIME', 5) * 60
    except User.DoesNotExist:
        email = ''
        expiry_seconds = getattr(settings, 'OTP_VALIDITY_TIME', 5) * 60
    
    context = {
        'form': form,
        'email': email,
        'expiry_seconds': expiry_seconds,
        'verify_action_url': 'auth:verify_otp_email',
        'resend_action_url': 'auth:resend_email_otp',
        'otp_title': 'Email Verification',
        'otp_heading': 'Verify Your Email',
        'otp_message': "We've sent a verification code to",
        'otp_button_label': 'Verify Email',
    }
    return render(request, 'authentication/verify_otp.html', context)


@require_http_methods(["POST"])
@csrf_protect
def resend_email_otp(request):
    """
    Resend OTP for email verification.
    Implements 30-second cooldown to prevent abuse.
    """
    user_id = request.session.get('verification_user_id')
    
    if not user_id:
        return JsonResponse({'error': 'No pending verification.'}, status=400)
    
    # Check cooldown in session
    last_resend = request.session.get('last_otp_resend')
    if last_resend:
        elapsed = timezone.now().timestamp() - last_resend
        if elapsed < 30:  # 30 second cooldown
            remaining = int(30 - elapsed)
            return JsonResponse({
                'error': f'Please wait {remaining} seconds before resending.'
            }, status=429)
    
    try:
        user = User.objects.get(id=user_id)
        
        # Check if user is already verified
        if user.is_email_verified:
            return JsonResponse({'error': 'Email already verified.'}, status=400)
        
        create_email_verification_otp(request, user)
        
        # Update session cooldown
        request.session['last_otp_resend'] = timezone.now().timestamp()
        
        return JsonResponse({'success': True, 'message': 'OTP sent successfully!'})
        
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found.'}, status=404)
    except Exception:
        return JsonResponse(
            {'error': 'Unable to resend OTP right now. Please try again shortly.'},
            status=500
        )
