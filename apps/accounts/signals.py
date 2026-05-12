"""
Django signals for accounts app.
Auto-generates OTP and sends verification email when a new user is created.
"""

import random
import string
from datetime import timedelta

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from django.conf import settings

from .models import User, UserProfile, OTPVerification


def generate_otp_code(length=6):
    """Generate a random OTP code of specified length."""
    return ''.join(random.choices(string.digits, k=length))


def send_otp_email(user, otp_code, expiry_minutes=5):
    """
    Send OTP verification email to user.
    Uses HTML template with plain text fallback.
    """
    subject = 'Your Email Verification Code'
    
    # Render HTML email template
    try:
        html_message = render_to_string('accounts/email/otp_email.html', {
            'user': user,
            'otp': otp_code,
            'expiry_minutes': expiry_minutes,
        })
    except Exception:
        # Fallback to simple HTML if template not found
        html_message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>Email Verification</h2>
            <p>Hello {user.email},</p>
            <p>Your verification code is:</p>
            <h1 style="background-color: #f0f0f0; padding: 15px; text-align: center; letter-spacing: 5px;">{otp_code}</h1>
            <p>This code will expire in {expiry_minutes} minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
        </body>
        </html>
        """
    
    # Create plain text version
    plain_message = strip_tags(html_message)
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
        fail_silently=False,
    )


def create_and_send_otp(user, login_log=None):
    """
    Create a new OTP and send it via email.
    Existing unverified OTPs are deleted only after the new email is sent successfully.
    This avoids leaving the user with no valid OTP if email delivery fails.
    """
    # Get expiry time from settings (default 5 minutes)
    expiry_minutes = getattr(settings, 'OTP_VALIDITY_TIME', 5)
    
    # Delete stale unverified OTPs
    stale_otps = OTPVerification.objects.filter(
        user=user,
        is_verified=False
    )
    stale_otp_ids = list(stale_otps.values_list('id', flat=True))
    
    # Generate new OTP code
    otp_length = getattr(settings, 'OTP_LENGTH', 6)
    otp_code = generate_otp_code(otp_length)
    
    # Calculate expiry time
    expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
    
    # Create new OTP
    otp = OTPVerification.objects.create(
        user=user,
        otp_code=otp_code,
        delivery_method='email',
        sent_to=user.email,
        expires_at=expires_at,
        login_log=login_log,
    )
    
    try:
        # Send OTP email
        send_otp_email(user, otp_code, expiry_minutes)
    except Exception as e:
        # If email fails, delete the OTP and re-raise the exception
        otp.delete()
        raise e
    
    # Clean up stale OTPs only after successful email sent
    if stale_otp_ids:
        OTPVerification.objects.filter(id__in=stale_otp_ids).delete()
    
    return otp


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create UserProfile when User is created."""
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def generate_otp_on_signup(sender, instance, created, **kwargs):
    """
    Signal handler that automatically generates an OTP and sends
    verification email when a new user registers.
    Only triggers when:
    - A new user is created (created=True)
    - User is not active (requires email verification)
    - Email is not already verified
    - User is NOT a staff/superuser (they bypass email verification)
    """
    # Skip OTP generation for staff/superuser accounts - they can login without email verification
    if instance.is_staff or instance.is_superuser:
        return
    
    if created and not instance.is_active and not instance.is_email_verified:
        try:
            create_and_send_otp(instance)
        except Exception:
            # Log the error but don't prevent user creation
            # In production, you might want to handle this more gracefully
            pass
