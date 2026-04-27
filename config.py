import os
import secrets
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

class Config:
    # Temel Flask ayarları
    
    # Key Rotation Sistemi
    _env_keys = os.environ.get('SECRET_KEYS') or os.environ.get('SECRET_KEY')
    if _env_keys:
        # Eğer virgülle ayrılmışsa liste yap, değilse tek elemanlı liste
        SECRET_KEYS = [k.strip() for k in _env_keys.split(',')]
    else:
        # Fallback (Production'da .env'de bu mutlaka tanımlanmalı!)
        SECRET_KEYS = ['change-me-in-production-and-security']

    if SECRET_KEYS == ['change-me-in-production-and-security']:
        raise RuntimeError("CRITICAL: SECRET_KEYS must be set in production!")
    
    # Flask standart uyumluluğu için ilk anahtarı set et
    SECRET_KEY = SECRET_KEYS[0] if SECRET_KEYS else None
    
    DATABASE_KEY = os.environ.get('DATABASE_KEY')
    LOG_ENCRYPTION_KEY = os.environ.get('LOG_ENCRYPTION_KEY')
    

    
    # Ana dizini al ve instance klasörünün tam yolunu belirle
    _basedir = os.path.abspath(os.path.dirname(__file__))
    _instance_path = os.path.join(_basedir, 'instance')
    
    # Instance klasörü yoksa otomatik oluştur (Önemli: SQLite klasör oluşturamaz)
    if not os.path.exists(_instance_path):
        os.makedirs(_instance_path)
        
    _db_path = os.path.join(_instance_path, 'users.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{_db_path}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # SQLCipher kaldırıldı (Standart SQLite)
    # Thread-safety için check_same_thread=False kullanımı
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "check_same_thread": False
        }
    }
    
    # Statik dosya cache süresi (1 Yıl) - Performans için kritik
    SEND_FILE_MAX_AGE_DEFAULT = 31536000
    
    # Dosya yükleme ayarları
    UPLOAD_FOLDER = 'app/static/profile_pics'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
    
    # Güvenlik ayarları
    SESSION_COOKIE_SECURE = True  # HTTPS zorunlu değil (Localhost/HTTP için)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_MAX_AGE = 3600  # 1 saat
    
    # CSRF koruması
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Rate limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = "memory://"
    
    # Güvenlik header'ları (HSTS aktif, CSP sıkılaştırıldı - Tor Ready)
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:* wss://127.0.0.1:*; font-src 'self'; frame-src 'none'; child-src 'none';",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    # Şifre politikası
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIREMENTS = {
        'uppercase': True,
        'lowercase': True,
        'numbers': True,
        'special_chars': False
    }
    
    # Session güvenliği
    SESSION_TIMEOUT = 3600  # 1 saat
    SESSION_REFRESH_EACH_REQUEST = True
    
    # Token ayarları
    TOKEN_EXPIRY = 3600  # 1 saat
    REMEMBER_TOKEN_EXPIRY = 30 * 24 * 3600  # 30 gün
    
    # Rate limiting ayarları (routes.py/middleware.py ile senkronize)
    MAX_REQUESTS_PER_MINUTE = 400          # Global limit
    MAX_LOGIN_ATTEMPTS = 10                # 5 dakikada 10 deneme
    LOGIN_LOCKOUT_TIME = 300               # 5 dakika kilitlenme süresi

    # CORS izin verilen kaynaklar — Wildcard '*' YASAK
    # Production için .env'de: ALLOWED_ORIGINS=https://keycord.org,https://www.keycord.org
    _allowed_origins_env = os.environ.get('ALLOWED_ORIGINS', '')
    ALLOWED_ORIGINS = (
        [o.strip() for o in _allowed_origins_env.split(',') if o.strip()]
        if _allowed_origins_env
        else ['http://127.0.0.1:8005', 'http://localhost:8005']  # Lab varsayılanı
    )
    
    # Dosya güvenliği
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_FILE_TYPES = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
    # Logging
    LOG_LEVEL = 'INFO'
    SECURITY_LOG_FILE = 'security.log'
    
    # API güvenliği
    API_RATE_LIMIT = 50  # API istekleri için dakikada maksimum
    API_TOKEN_EXPIRY = 3600  # API token süresi
    
    # Socket.IO güvenliği
    SOCKET_RATE_LIMIT = 100  # Socket bağlantıları için dakikada maksimum
    
    # Mesaj güvenliği
    MAX_MESSAGE_LENGTH = 1000
    MESSAGE_ENCRYPTION_ENABLED = True
    
    # Grup güvenliği
    MAX_GROUP_MEMBERS = 50
    MAX_GROUP_NAME_LENGTH = 50
    
    # Profil güvenliği
    MAX_USERNAME_LENGTH = 20
    MAX_ABOUT_LENGTH = 500
    MAX_GAMES_LENGTH = 200
    
    # Honeypot ayarları
    HONEYPOT_LIMIT = 20  # 1000'den 20'ye düşürüldü
    HONEYPOT_WINDOW = 600  # 10 dakika

    # Dil Ayarları
    LANGUAGES = ['tr', 'en', 'de']
    BABEL_DEFAULT_LOCALE = 'tr'
    BABEL_DEFAULT_TIMEZONE = 'Europe/Istanbul'
