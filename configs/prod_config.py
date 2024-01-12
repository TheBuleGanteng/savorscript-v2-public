# configs/dev_and_prod_config.py
import os


class ProductionConfig:
    
    # Get the base directory of your app
    BASEDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    # Development-specific configurations
    DEBUG = False

    # Use environment variables to get database file names
    DATABASE_URL = os.getenv('DATABASE_URL')

    # Remove 'sqlite:///' from the database_file string
    DATABASE_FILE = DATABASE_URL.replace('sqlite:///', '')

    # Construct the full path for the database file
    FULL_DATABASE_PATH = os.path.join(BASEDIR, DATABASE_FILE)

    # Database configuration
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{FULL_DATABASE_PATH}'
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