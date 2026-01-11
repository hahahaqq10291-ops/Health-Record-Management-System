"""
Production configuration for the Health Record Management System
Use this configuration when deploying to production environments like Render
"""
import os
from datetime import timedelta

class Config:
    """Base configuration"""
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CSRF Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    WTF_CSRF_SSL_STRICT = os.environ.get('FLASK_ENV') == 'production'
    
    # Email configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@lyfjshs.edu.ph')
    
    # Database
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'student_health.db')
    
    # Upload configuration
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB max file size
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'documents')
    
    # Security
    PREFERRED_URL_SCHEME = 'https'
    
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_SSL_STRICT = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_SSL_STRICT = True

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False

# Get configuration based on environment
config_name = os.environ.get('FLASK_ENV', 'production')
if config_name == 'development':
    config = DevelopmentConfig
elif config_name == 'testing':
    config = TestingConfig
else:
    config = ProductionConfig
