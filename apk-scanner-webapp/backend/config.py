import os
from datetime import timedelta

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'apk-scanner-secret-key'

    # Upload Configuration
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    ALLOWED_EXTENSIONS = {'apk'}

    # Analysis Configuration
    MAX_ANALYSIS_TIME = timedelta(minutes=10)
    ENABLE_DETAILED_LOGGING = True

    # Security Configuration
    ENABLE_RATE_LIMITING = True
    MAX_REQUESTS_PER_HOUR = 50

    # AI Analysis Configuration
    AI_CONFIDENCE_THRESHOLD = 0.7
    MALWARE_SCORE_THRESHOLD = 60

class DevelopmentConfig(Config):
    DEBUG = True
    ENABLE_DETAILED_LOGGING = True

class ProductionConfig(Config):
    DEBUG = False
    ENABLE_DETAILED_LOGGING = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
