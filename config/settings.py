"""
Django settings for AI-Based Behavioral Authentication System.
Production-ready configuration.
"""

import os
from pathlib import Path
from datetime import timedelta

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

env_file = BASE_DIR / '.env'
if env_file.exists():
    for line in env_file.read_text(encoding='utf-8').splitlines():
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith('#') or '=' not in stripped_line:
            continue
        key, value = stripped_line.split('=', 1)
        cleaned_value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), cleaned_value)


def env_bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in {'1', 'true', 'yes', 'on'}


def env_list(name, default=''):
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(',') if item.strip()]

# Secret key - loaded from environment variable
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-change-me')

# Security - Set DEBUG via environment in production
DEBUG = env_bool('DEBUG', False)
ALLOWED_HOSTS = env_list('ALLOWED_HOSTS', 'localhost,127.0.0.1')
CSRF_TRUSTED_ORIGINS = env_list('CSRF_TRUSTED_ORIGINS')

# SECURITY SETTINGS
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_SECURITY_POLICY = {
    "default-src": ("'self'",),
    "script-src": ("'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"),
    "style-src": ("'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"),
    "img-src": ("'self'", "data:", "https:"),
    "font-src": ("'self'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"),
    "connect-src": ("'self'",),
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Local apps
    'apps.accounts',
    'apps.authentication',
    'apps.dashboard',
    'apps.behavior_tracking',
    'apps.ml_engine',
    'apps.adminpanel',
    'apps.reports',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Custom middleware
    'apps.accounts.middleware.LoginAttemptMiddleware',
    'apps.accounts.middleware.SessionTimeoutMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# Database - SQLite3
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Authentication settings
AUTH_USER_MODEL = 'accounts.User'
LOGIN_URL = 'auth:login'
LOGIN_REDIRECT_URL = 'dashboard:home'
LOGOUT_REDIRECT_URL = 'home'

# Session settings
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
SECURE_SSL_REDIRECT = env_bool('SECURE_SSL_REDIRECT', not DEBUG)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = int(os.getenv('SECURE_HSTS_SECONDS', '31536000' if not DEBUG else '0'))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', not DEBUG)
SECURE_HSTS_PRELOAD = env_bool('SECURE_HSTS_PRELOAD', not DEBUG)

# Login attempts and OTP settings
MAX_LOGIN_ATTEMPTS = int(os.getenv('LOGIN_ATTEMPT_LIMIT', '5'))
LOGIN_ATTEMPT_TIMEOUT = int(os.getenv('LOGIN_ATTEMPT_TIMEOUT', '15'))  # minutes
OTP_VALIDITY_TIME = int(os.getenv('OTP_VALIDITY_TIME', '5'))  # minutes
OTP_LENGTH = int(os.getenv('OTP_LENGTH', '6'))
MAX_OTP_ATTEMPTS = int(os.getenv('OTP_MAX_ATTEMPTS', '3'))

# IP-based rate limiting
IP_RATE_LIMIT = int(os.getenv('IP_RATE_LIMIT', '20'))  # max login attempts per IP per hour
IP_RATE_LIMIT_WINDOW = 3600  # seconds (1 hour)

# For production SMTP:
EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', 'django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True') == 'True'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', EMAIL_HOST_USER or 'noreply@aiauth.local')

# Machine Learning settings
ML_MODELS_DIR = BASE_DIR / 'ml' / 'models'
ML_MODEL_ACCURACY_THRESHOLD = 0.75
TRUST_SCORE_SAFE = int(os.getenv('TRUST_SCORE_SAFE', '75'))
TRUST_SCORE_SUSPICIOUS = int(os.getenv('TRUST_SCORE_SUSPICIOUS', '45'))

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'debug.log',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
    },
}

# Create ML models directory if it doesn't exist
ML_MODELS_DIR.mkdir(parents=True, exist_ok=True)
