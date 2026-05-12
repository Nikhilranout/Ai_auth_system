"""
Custom middleware for accounts app.
"""

from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.conf import settings
from datetime import timedelta


class LoginAttemptMiddleware(MiddlewareMixin):
    """Middleware to handle login attempt tracking and account locking."""
    
    def process_request(self, request):
        """Process request to check login attempts."""
        # Check if user account is locked
        if request.user and request.user.is_authenticated:
            if request.user.is_account_locked:
                last_attempt = request.user.last_login_attempt
                timeout_minutes = settings.LOGIN_ATTEMPT_TIMEOUT
                
                if last_attempt and (timezone.now() - last_attempt) > timedelta(minutes=timeout_minutes):
                    # Unlock account after timeout
                    request.user.is_account_locked = False
                    request.user.login_attempts = 0
                    request.user.save()
        
        return None


class SessionTimeoutMiddleware(MiddlewareMixin):
    """Middleware to handle session timeout."""
    
    def process_request(self, request):
        """Process request to check session timeout."""
        
        if request.user.is_authenticated:
            # Check session age
            last_activity = request.session.get('last_activity')
            session_timeout = settings.SESSION_COOKIE_AGE  # in seconds
            
            if last_activity:
                if isinstance(last_activity, (int, float)):
                    elapsed = timezone.now().timestamp() - last_activity
                else:
                    # Older sessions may still contain a non-JSON-safe value.
                    request.session.pop('last_activity', None)
                    elapsed = 0
                
                if elapsed > session_timeout:
                    # Session has expired
                    from django.contrib.auth import logout
                    logout(request)
                    return None
            
            # Update last activity
            request.session['last_activity'] = timezone.now().timestamp()
        
        return None
