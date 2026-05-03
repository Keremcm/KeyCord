import re
import json
import hashlib
import secrets
import time
import requests
from functools import wraps
from flask import request, jsonify, session, current_app, g, redirect, flash
from flask_socketio import emit
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from collections import defaultdict
import logging
from logging.handlers import RotatingFileHandler

# Rate limiting için basit bir in-memory store
rate_limit_store = defaultdict(list)
failed_login_attempts = defaultdict(int)
failed_login_timestamps = defaultdict(list)

# Güvenlik konfigürasyonu
SECURITY_CONFIG = {
    'MAX_LOGIN_ATTEMPTS': 10,
    'LOGIN_LOCKOUT_TIME': 300,  # 5 dakika
    'RATE_LIMIT_WINDOW': 60,    # 1 dakika
    'MAX_REQUESTS_PER_WINDOW': 400,
    'PASSWORD_MIN_LENGTH': 8,
    'PASSWORD_REQUIREMENTS': {
        'uppercase': True,
        'lowercase': True,
        'numbers': True,
        'special_chars': False
    },
    'SESSION_TIMEOUT': 3600,  # 1 saat
    'TOKEN_EXPIRY': 3600,     # 1 saat
    'ALLOWED_FILE_TYPES': {'png', 'jpg', 'jpeg', 'gif', 'webp'},
    'MAX_FILE_SIZE': 5 * 1024 * 1024,  # 5MB
    'XSS_PATTERNS': [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<form[^>]*>',
        r'<input[^>]*>',
        r'<textarea[^>]*>',
        r'<select[^>]*>'
    ],
    'MALICIOUS_PATTERNS': [
        r'wget', r'curl', r'chmod', r'rm\s+-rf', r'sudo\s+',
        r'cat\s+/etc', r'base64', r'phpinfo', r'system\(',
        r'exec\(', r'passthru', r'shell_exec', r'union\s+select',
        r'order\s+by'
    ]
}

def setup_security_logging():
    """Güvenlik logları için özel logger kurulumu"""
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    
    if not security_logger.handlers:
        # 10MB boyuta ulaşınca rotasyon yap, en fazla 5 yedek tut
        handler = RotatingFileHandler('security.log', maxBytes=10*1024*1024, backupCount=5)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        security_logger.addHandler(handler)
    
    return security_logger

security_logger = setup_security_logging()

def get_remote_addr():
    """Gerçek IP adresini döndürür (Cloudflare ve Proxy desteğiyle)"""
    # Cloudflare başlığına öncelik ver
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip and cf_ip != '127.0.0.1':
        return cf_ip
        
    # X-Forwarded-For listesini tara
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        ips = [i.strip() for i in forwarded.split(',')]
        for ip in ips:
            if ip and not ip.startswith('127.') and not ip.startswith('192.168.'):
                return ip
                
    # Diğer standart başlıklar
    real_ip = request.headers.get('X-Real-IP')
    if real_ip and real_ip != '127.0.0.1':
        return real_ip
        
    return request.remote_addr

def log_security_event(event_type, details, user_id=None, ip_address=None):
    """Güvenlik olaylarını loglar (Şifreli)"""
    from cryptography.fernet import Fernet
    
    log_data = {
        'event_type': event_type,
        'details': details,
        'user_id': user_id,
        'ip_address': ip_address or get_remote_addr(),
        'user_agent': request.headers.get('User-Agent', ''),
        'timestamp': datetime.datetime.utcnow().isoformat()
    }
    
    log_string = json.dumps(log_data)
    
    # Şifreleme anahtarını al
    encryption_key = current_app.config.get('LOG_ENCRYPTION_KEY')
    
    if encryption_key:
        try:
            f = Fernet(encryption_key.encode())
            encrypted_data = f.encrypt(log_string.encode()).decode()
            security_logger.info(f"ENCRYPTED_EVENT: {encrypted_data}")
        except Exception as e:
            # Şifreleme hatası (Anahtar geçersiz vb.)
            security_logger.error(f"LOG_ENCRYPTION_ERROR: {str(e)}")
            security_logger.info(f"SECURITY_EVENT: {log_string}")
    else:
        # Anahtar yoksa şifrelemeden logla (Geriye dönük uyumluluk/Setup aşaması)
        security_logger.info(f"SECURITY_EVENT: {log_string}")

def sanitize_input(text):
    """XSS ve injection saldırılarına karşı input temizleme"""
    if not text:
        return text
    
    text = str(text)
    
    # XSS pattern'lerini kontrol et
    for pattern in SECURITY_CONFIG['XSS_PATTERNS']:
        if re.search(pattern, text, re.IGNORECASE):
            log_security_event('XSS_ATTEMPT', f'Pattern detected: {pattern}', 
                             user_id=session.get('user_id'))
            return None
    
    # HTML karakterlerini escape et
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    text = text.replace('"', '&quot;').replace("'", '&#x27;')
    
    return text

def validate_password_strength(password):
    """Şifre gücünü kontrol eder"""
    if len(password) < SECURITY_CONFIG['PASSWORD_MIN_LENGTH']:
        return False, f"Şifre en az {SECURITY_CONFIG['PASSWORD_MIN_LENGTH']} karakter olmalıdır."
    
    requirements = SECURITY_CONFIG['PASSWORD_REQUIREMENTS']
    
    if requirements['uppercase'] and not re.search(r'[A-Z]', password):
        return False, "Şifre en az bir büyük harf içermelidir."
    
    if requirements['lowercase'] and not re.search(r'[a-z]', password):
        return False, "Şifre en az bir küçük harf içermelidir."
    
    if requirements['numbers'] and not re.search(r'\d', password):
        return False, "Şifre en az bir rakam içermelidir."
    
    if requirements['special_chars'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Şifre en az bir özel karakter içermelidir."
    
    return True, "Şifre güvenli."

def is_malicious_request(text):
    """URL veya gövdede zararlı komut/pattern kontrolü"""
    if not text:
        return False
    from urllib.parse import unquote
    decoded_text = unquote(str(text))
    for pattern in SECURITY_CONFIG['MALICIOUS_PATTERNS']:
        if re.search(pattern, decoded_text, re.IGNORECASE):
            return True
    return False

def check_ban_cookie():
    """Banned çerezi kontrolü"""
    return request.cookies.get('kcord_status') == 'banned'

def load_banned_ips():
    """Dosyadan yasaklı IP'leri yükle"""
    import os
    banned_file = os.path.join(os.getcwd(), 'banned_ips.txt')
    if not os.path.exists(banned_file):
        return set()
    try:
        with open(banned_file, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    except Exception:
        return set()

def save_banned_ip(ip):
    """IP'yi dosyaya kalıcı olarak kaydet"""
    import os
    banned_file = os.path.join(os.getcwd(), 'banned_ips.txt')
    try:
        with open(banned_file, 'a') as f:
            f.write(f"{ip}\n")
    except Exception:
        pass

def rate_limit_check(identifier, max_requests=None, window=None, request_type='general'):
    """Veritabanı tabanlı ve şifreli rate limiting kontrolü"""
    from .models import RateLimit
    from . import db
    from cryptography.fernet import Fernet
    
    if max_requests is None:
        max_requests = SECURITY_CONFIG['MAX_REQUESTS_PER_WINDOW']
    if window is None:
        window = SECURITY_CONFIG['RATE_LIMIT_WINDOW']
    
    # Identifier (IP) için SHA-256 hash oluştur (Arama için)
    id_hash = hashlib.sha256(identifier.encode()).hexdigest()
    
    current_time = datetime.datetime.utcnow()
    window_start = current_time - datetime.timedelta(seconds=window)
    
    # Veritabanından son penceredeki istek sayısını sorgula
    request_count = RateLimit.query.filter(
        RateLimit.identifier_hash == id_hash,
        RateLimit.request_type == request_type,
        RateLimit.timestamp >= window_start
    ).count()
    
    if request_count >= max_requests:
        log_security_event('RATE_LIMIT_EXCEEDED', f'Identifier: {identifier}, Type: {request_type}')
        return False
    
    # Yeni isteği kaydet
    try:
        # IP'yi Fernet ile şifrele (Opsiyonel denetim için)
        encrypted_id = None
        encryption_key = current_app.config.get('LOG_ENCRYPTION_KEY')
        if encryption_key:
            f = Fernet(encryption_key.encode())
            encrypted_id = f.encrypt(identifier.encode()).decode()

        new_entry = RateLimit(
            identifier_hash=id_hash,
            encrypted_identifier=encrypted_id,
            request_type=request_type,
            timestamp=current_time
        )
        db.session.add(new_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"RateLimit save error: {e}")
    
    return True

def check_login_attempts(identifier):
    """Başarısız giriş denemelerini DB üzerinden kontrol eder"""
    # Login denemeleri için rate_limit_check'i kullan
    return rate_limit_check(
        identifier, 
        max_requests=SECURITY_CONFIG['MAX_LOGIN_ATTEMPTS'], 
        window=SECURITY_CONFIG['LOGIN_LOCKOUT_TIME'],
        request_type='login_fail'
    )

def record_failed_login(identifier):
    """Başarısız giriş denemesini DB'ye kaydeder"""
    # rate_limit_check zaten kayıt yapıyor, 
    # ancak başarısız girişi tetiklemek için burada bir kayıt oluşturabiliriz.
    # Bu fonksiyon sadece log basmak için kullanılabilir veya manuel kayıt atar.
    log_security_event('FAILED_LOGIN', f'Identifier: {identifier}')
    # Kayıt işlemi check_login_attempts veya rate_limit_check tarafından yapılacağı için 
    # burada ekstra bir işlem yapmaya gerek kalmayabilir, ancak mevcut akışı bozmamak için:
    pass 

def clear_failed_login_attempts(identifier):
    """Başarılı giriş sonrası DB'deki eski login_fail kayıtlarını temizler (Opsiyonel)"""
    from .models import RateLimit
    from . import db
    id_hash = hashlib.sha256(identifier.encode()).hexdigest()
    try:
        RateLimit.query.filter_by(identifier_hash=id_hash, request_type='login_fail').delete()
        db.session.commit()
    except Exception:
        db.session.rollback()

def validate_file_upload(filename, file_size):
    """Dosya yükleme güvenlik kontrolü"""
    if not filename:
        return False, "Dosya adı boş olamaz."
    
    # Dosya uzantısı kontrolü
    file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if file_ext not in SECURITY_CONFIG['ALLOWED_FILE_TYPES']:
        log_security_event('INVALID_FILE_TYPE', f'File: {filename}')
        return False, "Geçersiz dosya türü."
    
    # Dosya boyutu kontrolü
    if file_size > SECURITY_CONFIG['MAX_FILE_SIZE']:
        log_security_event('FILE_TOO_LARGE', f'File: {filename}, Size: {file_size}')
        return False, "Dosya boyutu çok büyük."
    
    # Dosya adı güvenlik kontrolü
    if re.search(r'[<>:"/\\|?*]', filename):
        log_security_event('MALICIOUS_FILENAME', f'File: {filename}')
        return False, "Geçersiz dosya adı."
    
    return True, "Dosya güvenli."

def generate_secure_token(user_id, additional_data=None):
    """Güvenli token oluşturur (Versioning destekli)"""
    from .models import User
    user = User.query.get(user_id)
    t_version = user.token_version if user else 1

    payload = {
        'user_id': user_id,
        'token_version': t_version,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=SECURITY_CONFIG['TOKEN_EXPIRY']),
        'iat': datetime.datetime.utcnow(),
        'jti': secrets.token_urlsafe(16),  # JWT ID
        'additional_data': additional_data or {}
    }
    
    secret = current_app.config['SECRET_KEY']
    return jwt.encode(payload, secret, algorithm='HS256')

def verify_secure_token(token):
    """Güvenli token doğrulama (Versioning kontrolü dahil)"""
    try:
        secret = current_app.config['SECRET_KEY']
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        
        user_id = payload.get('user_id')
        token_ver = payload.get('token_version')

        # Token versiyon kontrolü
        from .models import User
        user = User.query.get(user_id)
        if not user or token_ver != user.token_version:
            log_security_event('INVALID_TOKEN_VERSION', f'User: {user_id}')
            return None
            
        return user_id
    except jwt.ExpiredSignatureError:
        log_security_event('TOKEN_EXPIRED', 'Token süresi dolmuş')
        return None
    except jwt.InvalidTokenError:
        log_security_event('INVALID_TOKEN', 'Geçersiz token')
        return None

def require_auth(f):
    """Authentication gerektiren decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        
        if not user_id:
            # API istekleri için token kontrolü
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                user_id = verify_secure_token(token)
            
            if not user_id:
                log_security_event('UNAUTHORIZED_ACCESS', f'Route: {request.endpoint}')
                if request.is_json:
                    return jsonify({'error': 'Yetkilendirme gerekli.'}), 401
                return redirect('/login')
        
        g.current_user_id = user_id
        return f(*args, **kwargs)
    return decorated_function

def require_api_auth(f):
    """API endpoints için Bearer Token authentication gerektiren decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Header'dan token al
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
             return jsonify({'error': 'Token gerekli.'}), 401

        # 2. Token'ı doğrula
        user_id = verify_secure_token(token)
        if not user_id:
             return jsonify({'error': 'Geçersiz veya süresi dolmuş token.'}), 401
        
        # 3. User ID'yi global değişkene ata
        g.current_user_id = user_id
        return f(*args, **kwargs)
    return decorated_function

def require_csrf(f):
    """CSRF koruması için decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            session_token = session.get('csrf_token')
            
            if not csrf_token or not session_token or csrf_token != session_token:
                log_security_event('CSRF_ATTEMPT', f'Route: {request.endpoint}')
                if request.is_json:
                    return jsonify({'error': 'CSRF token geçersiz.'}), 403
                flash('Güvenlik hatası. Lütfen tekrar deneyin.')
                return redirect(request.referrer or '/')
        
        return f(*args, **kwargs)
    return decorated_function

def generate_csrf_token():
    """CSRF token oluşturur"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_user_input(data, required_fields=None, optional_fields=None):
    """Kullanıcı input validasyonu"""
    if required_fields:
        for field in required_fields:
            if field not in data or not data[field]:
                return False, f"'{field}' alanı gerekli."
    
    # Tüm string alanları sanitize et
    for key, value in data.items():
        if isinstance(value, str):
            sanitized = sanitize_input(value)
            if sanitized is None:
                return False, f"'{key}' alanında geçersiz karakterler bulundu."
            data[key] = sanitized
    
    return True, "Input geçerli."

def socket_auth_required(f):
    """Socket.IO için authentication decorator"""
    @wraps(f)
    def decorated_function(data):
        user_id = None
        token = data.get('token')
        if token:
            user_id = verify_secure_token(token)
            if not user_id:
                user_id = None

        if not user_id:
            # Session fallback: WebSocket oturumları da session cookie ile çalışır
            user_id = session.get('user_id')

        if not user_id:
            emit('error', {'message': 'Oturum doğrulaması başarısız. Lütfen tekrar giriş yapın.'})
            return
        
        # Rate limiting kontrolü
        if not rate_limit_check(f"socket_{user_id}", 50, 60):
            emit('error', {'message': 'Çok fazla istek. Lütfen bekleyin.'})
            return
        
        return f(data)
    return decorated_function

def add_security_headers(response):
    """Güvenlik header'larını ekler (Nonce tabanlı CSP dahil)"""
    from flask import g
    nonce = getattr(g, 'csp_nonce', '')
    
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # CSP: Script'ler için nonce şart, Style'lar için 'unsafe-inline' (Görüntü için serbest)
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"font-src 'self' data:; "
        f"img-src 'self' data:; "
        f"connect-src 'self' ws: wss:; "
        f"frame-src 'none'; "
        f"child-src 'none';"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

def validate_group_access(user_id, group_id, groups):
    """Grup erişim kontrolü"""
    group = next((g for g in groups if g['id'] == group_id), None)
    if not group:
        log_security_event('UNAUTHORIZED_GROUP_ACCESS', f'User: {user_id}, Group: {group_id}')
        return False
    return True

def validate_friendship(user_id, friend_id):
    """Arkadaşlık kontrolü"""
    try:
        from .models import Friendship
        friendship = Friendship.query.filter_by(user_id=user_id, friend_id=friend_id).first()
        if not friendship:
            log_security_event('UNAUTHORIZED_FRIEND_ACCESS', f'User: {user_id}, Friend: {friend_id}')
            return False
        return True
    except Exception as e:
        log_security_event('FRIENDSHIP_CHECK_ERROR', f'Error: {str(e)}, User: {user_id}, Friend: {friend_id}')
        return False

def sanitize_message_content(content):
    """Mesaj içeriği sanitizasyonu"""
    if not content or len(content.strip()) == 0:
        return None
    
    # Maksimum mesaj uzunluğu
    if len(content) > 1000:
        return None
    
    # XSS ve injection temizleme
    sanitized = sanitize_input(content.strip())
    if sanitized is None:
        return None
    
    return sanitized

def validate_username(username):
    """Kullanıcı adı validasyonu"""
    if not username or len(username.strip()) < 3 or len(username.strip()) > 20:
        return False, "Kullanıcı adı 3-20 karakter arasında olmalıdır."
    
    # Sadece alfanumerik karakterler ve _.-
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username.strip()):
        return False, "Kullanıcı adı sadece harf, rakam ve _.- içerebilir."
    
    return True, "Kullanıcı adı geçerli."




