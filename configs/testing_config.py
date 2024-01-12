import os


class TestingConfig:
    
    # Get the base directory of your app
    BASEDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    # Development-specific configurations
    DEBUG = True


    # Database configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session configuration
    SESSION_PERMANENT = False
    SESSION_TYPE = 'filesystem'

    # Email server configuration for development
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False

    # Get the port number from the PORT environment variable (default is 10000)
    PORT = int(os.getenv('PORT', 5000))

    # Token settings
    MAX_TOKEN_AGE_SECONDS = 900
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY') or 'default-dev-secret-key'

    # Content Security Policy for Talisman
    CONTENT_SECURITY_POLICY = {
        'default-src': [
            '\'self\'',
            'https://cdn.jsdelivr.net',
        ],
        'script-src': [
            '\'self\'',
            'https://cdn.jsdelivr.net',
        ],
        'style-src': [
            '\'self\'',
            'https://cdn.jsdelivr.net',
            '\'unsafe-inline\'',
        ],
        'img-src': [
            "'self'",
            "data:",  # Allows data URIs for images
        ],
        'report-uri': '/csp-violation-report'
    }