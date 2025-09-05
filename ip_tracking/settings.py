# Add these settings to your existing settings.py file

# ... existing settings ...

# Add the ip_tracking app to INSTALLED_APPS
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'django_ratelimit',
    
    # Local apps
    'ip_tracking',
    
    # ... your other apps ...
]

# Middleware configuration - ORDER MATTERS!
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
    # IP Tracking Middleware - should be early in the stack
    'ip_tracking.middleware.IPTrackingMiddleware',
    
    # ... your other middleware ...
]

# Cache configuration for IP tracking (Redis recommended for production)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'ip_tracking',
        'TIMEOUT': 300,  # Default cache timeout (5 minutes)
    }
}

# Alternative cache configuration for development (using database)
# CACHES = {
#     'default': {
#         'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
#         'LOCATION': 'cache_table',
#     }
# }

# Django Rate Limit Configuration
RATELIMIT_ENABLE = True  # Set to False to disable rate limiting
RATELIMIT_USE_CACHE = 'default'  # Use the default cache for rate limiting

# Custom rate limit handler
RATELIMIT_VIEW = 'ip_tracking.views.ratelimited'

# Celery Configuration for Background Tasks
import os

# Celery broker configuration (Redis recommended)
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

# Celery task configuration
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'

# Celery Beat Schedule for Periodic Tasks
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'detect-suspicious-ips': {
        'task': 'ip_tracking.tasks.detect_suspicious_ips',
        'schedule': crontab(minute=0),  # Run every hour
    },
    'auto-block-persistent-ips': {
        'task': 'ip_tracking.tasks.auto_block_persistent_suspicious_ips',
        'schedule': crontab(hour=2, minute=0),  # Run daily at 2 AM
    },
    'cleanup-old-logs': {
        'task': 'ip_tracking.tasks.cleanup_old_logs',
        'schedule': crontab(hour=3, minute=0),  # Run daily at 3 AM
    },
    'generate-security-report': {
        'task': 'ip_tracking.tasks.generate_security_report',
        'schedule': crontab(hour=8, minute=0),  # Run daily at 8 AM
    },
}

# Logging configuration for IP tracking
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'ip_tracking.log'),
            'maxBytes': 1024*1024*5,  # 5 MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'security.log'),
            'maxBytes': 1024*1024*10,  # 10 MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'ip_tracking': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'security': {
            'handlers': ['security_file', 'console'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}

# Ensure logs directory exists
import os
os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)

# Security settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# IP Tracking specific settings
IP_TRACKING_SETTINGS = {
    'MAX_REQUESTS_PER_HOUR': 100,
    'GEOLOCATION_API_TIMEOUT': 5,
    'CACHE_GEOLOCATION_HOURS': 24,
    'SENSITIVE_PATHS': [
        '/admin',
        '/login',
        '/api/admin',
        '/dashboard/admin',
        '/wp-admin',
        '/phpmyadmin',
        '/admin.php',
        '/administrator'
    ],
    'SKIP_PATHS': [
        '/favicon.ico',
        '/robots.txt',
        '/static/',
        '/media/',
        '/health/',
    ],
    'AUTO_BLOCK_THRESHOLD': 3,  # Auto-block after 3 suspicious flags
    'LOG_RETENTION_DAYS': 30,
}

# Rate limiting settings
RATELIMIT_SETTINGS = {
    'AUTHENTICATED_RATE': '10/m',
    'ANONYMOUS_RATE': '5/m',
    'API_RATE': '20/m',
    'ADMIN_RATE': '30/m',
}

# Database configuration note:
# Make sure to run these commands after adding the models:
# python manage.py makemigrations ip_tracking
# python manage.py migrate

# For cache table (if using database cache):
# python manage.py createcachetable