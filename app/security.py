import re
import json
import hashlib
import secrets
import time
import os
import threading
import concurrent.futures
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


# ── Hızlı In-Memory Per-IP Kapıları (DB yazmadan önce) ──────────────
class MemoryRateLimiter:
    """Sabit pencere bazlı, DB'ye hiç yazmayan per-IP hızlı kapı.

    Amacı: normal trafikte DB'ye satır yazmadan istek akışını süzmek;
    yalnızca pencere dolduğunda kalıcı DB kontrolüne (rate_limit_check)
    geçmek. Böylece tek bir IP'nin flood'u tüm siteyi SQLite yazma
    yarışına sokmaz; yavaşlayan yalnızca o IP olur.
    """
    MAX_KEYS = 100000  # Bellek güvenliği: aşırı benzersiz IP'de kovayı sıfırla

    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._records = defaultdict(list)
        self._lock = threading.Lock()

    def _prune(self, key, now):
        bucket = self._records.get(key)
        if bucket is None:
            return []
        alive = [t for t in bucket if now - t < self.window_seconds]
        if alive:
            self._records[key] = alive
        else:
            self._records.pop(key, None)
        return alive

    def allow(self, key):
        now = time.time()
        with self._lock:
            if len(self._records) > self.MAX_KEYS:
                self._records.clear()
            bucket = self._prune(key, now)
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            self._records[key] = bucket
            return True

    def peek(self, key):
        now = time.time()
        with self._lock:
            bucket = self._prune(key, now)
            return len(bucket) < self.max_requests

    def reset(self, key):
        with self._lock:
            self._records.pop(key, None)


# ── CPU-Yoğun İşlem Havuzu (eventlet döngüsünü bloklamamak için) ────
_cpu_executor = None

def run_cpu_bound(func, *args, **kwargs):
    """CPU-yoğun işlemleri eventlet döngüsünden gerçek OS thread'ine taşır.

    eventlet aktifken (monkey-patch yapılmışsa) döngüyü bloklamamak için
    eventlet.tpool kullanılır; değilse concurrent.futures executor devreye
    girer. PBKDF2 gibi işlemler tek thread'de koştuğunda tüm siteyi
    dondurduğu için login/register akışında kullanılmalıdır.
    """
    global _cpu_executor
    try:
        import eventlet
        if eventlet.patcher.original:
            return eventlet.tpool.execute(func, *args, **kwargs)
    except Exception:
        pass

    if _cpu_executor is None:
        _cpu_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix='cpu'
        )
    return _cpu_executor.submit(func, *args, **kwargs).result()

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

# Genel istek akışı için per-IP hızlı kapı (DB cap ile senkron, 400/dk)
memory_global_limiter = MemoryRateLimiter(
    max_requests=SECURITY_CONFIG['MAX_REQUESTS_PER_WINDOW'],
    window_seconds=SECURITY_CONFIG['RATE_LIMIT_WINDOW']
)
# Login/register flood'unu DB'ye taşımadan durduran per-IP hızlı kapılar
memory_login_limiter = MemoryRateLimiter(max_requests=15, window_seconds=60)
memory_register_limiter = MemoryRateLimiter(max_requests=6, window_seconds=60)

# ── AI Bot Whitelist ────────────────────────────────────────────────
# User-Agent içinde bu stringlerden herhangi biri geçen istekler
# public sayfalarda tüm güvenlik kontrollerinden (rate-limit, IP ban,
# CSRF, session kontrolü) tamamen muaf tutulur.
# Büyük/küçük harf duyarsız substring eşleşmesi yapılır.
BOT_WHITELIST = [
    'google', 'chatgpt', 'claude', 'anthropic',
    'GPTBot', 'ChatGPT-User', 'OAI-SearchBot',
    'ClaudeBot', 'Claude-Web', 'anthropic-ai',
    'Gemini', 'Googlebot', 'Google-Read-Aloud', 'AdsBot-Google',
    'DeepSeek', 'Bytespider', 'PerplexityBot',
    'Amazonbot', 'Applebot',
]

PUBLIC_PATHS = frozenset({
    '/', '/login', '/register', '/forgot-password',
    '/help-center', '/faq', '/contact',
    '/privacy-policy', '/terms-of-service', '/gdpr', '/kvkk',
    '/canary', '/hall-of-fame', '/careers',
    '/sitemap.xml', '/robots.txt', '/security.txt',
})

def is_allowed_bot(user_agent):
    """User-Agent içindeki bot whitelist eşleşmesini kontrol eder (case-insensitive)."""
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    return any(bot.lower() in ua_lower for bot in BOT_WHITELIST)

def is_bot_on_public_page():
    """Whitelist'teki bir bot public sayfada mı diye kontrol eder."""
    from flask import request
    ua = request.headers.get('User-Agent', '')
    path = request.path.rstrip('/') or '/'
    if not is_allowed_bot(ua):
        return False
    if path in PUBLIC_PATHS:
        return True
    if path.startswith('/') and path.split('/')[0] in PUBLIC_PATHS:
        return False
    return path in PUBLIC_PATHS

def setup_security_logging():
    """Güvenlik logları için özel logger kurulumu"""
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False  # Root logger'a (terminal) yansıma
    
    if not security_logger.handlers:
        log_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "security.log")
        handler = RotatingFileHandler(log_path, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
        formatter = logging.Formatter('%(message)s')
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

def _parse_banned_line(line):
    """banned_ips.txt satırını (ip, reason) olarak ayrıştırır. Geçersizse (None, None)."""
    import ipaddress
    line = line.strip()
    if not line or line.startswith('#'):
        return None, None
    ip, sep, reason = line.partition('|')
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    return ip, (reason.strip() if sep else None)


_banned_entries_cache = {"mtime": None, "entries": []}


def load_banned_entries():
    """banned_ips.txt içindeki (ip, reason) girdilerini listeler.

    Dosyanın mtime'ı değişmediği sürece önbellekli döner; dosya değişirse
    bir sonraki çağrıda taze olarak yeniden parse edilir (anlık güncel).
    """
    import os
    banned_file = os.path.join(os.getcwd(), 'banned_ips.txt')
    try:
        mtime = os.path.getmtime(banned_file)
    except OSError:
        mtime = None
    if _banned_entries_cache["mtime"] == mtime:
        return _banned_entries_cache["entries"]
    entries = []
    if mtime is not None:
        with open(banned_file, 'r') as f:
            for line in f:
                ip, reason = _parse_banned_line(line)
                if ip:
                    entries.append((ip, reason))
    _banned_entries_cache["mtime"] = mtime
    _banned_entries_cache["entries"] = entries
    return entries


class DynamicBlockedIPs(set):
    """Dosya değişimini (mtime) izleyen ve güncellendiğinde kendini otomatik yenileyen dinamik IP listesi"""
    def __init__(self):
        super().__init__()
        import os
        self._filepath = os.path.join(os.getcwd(), 'banned_ips.txt')
        self._last_mtime = 0
        self._reload_if_modified()

    def _reload_if_modified(self):
        import os
        if not os.path.exists(self._filepath):
            if len(self) > 0:
                super().clear()
                self._last_mtime = 0
            return
        try:
            mtime = os.path.getmtime(self._filepath)
            if mtime > self._last_mtime:
                ips = {ip for ip, _ in load_banned_entries()}
                super().clear()
                super().update(ips)
                self._last_mtime = mtime
        except Exception:
            pass

    def __contains__(self, item):
        self._reload_if_modified()
        return super().__contains__(item)

    def add(self, element):
        self._reload_if_modified()
        super().add(element)
        import os
        try:
            if os.path.exists(self._filepath):
                self._last_mtime = os.path.getmtime(self._filepath)
        except Exception:
            pass

    def __iter__(self):
        self._reload_if_modified()
        return super().__iter__()

    def __len__(self):
        self._reload_if_modified()
        return super().__len__()

def load_banned_ips():
    """Dosyadan yasaklı IP'leri dinamik ve otomatik güncellenen bir şekilde yükle"""
    return DynamicBlockedIPs()


def save_banned_ip(ip, reason=None):
    """IP'yi dosyaya kalıcı olarak kaydet (opsiyonel sebeple: `IP | sebep`)"""
    import os
    banned_file = os.path.join(os.getcwd(), 'banned_ips.txt')
    try:
        with open(banned_file, 'a') as f:
            if reason:
                f.write(f"{ip} | {reason}\n")
            else:
                f.write(f"{ip}\n")
    except Exception:
        pass

HONEYTOKEN_CREDS_FILE = 'honeytoken_creds.json'

def save_honeytoken_cred(username, password):
    """Saldırganın honeypot formuna girdiği verileri şifreli olarak kaydeder."""
    import json
    import os
    import time
    from cryptography.fernet import Fernet
    
    encryption_key = current_app.config.get('LOG_ENCRYPTION_KEY')
    if not encryption_key: return
    
    f = Fernet(encryption_key.encode())
    
    creds = []
    if os.path.exists(HONEYTOKEN_CREDS_FILE):
        try:
            with open(HONEYTOKEN_CREDS_FILE, 'rb') as file:
                decrypted_data = f.decrypt(file.read()).decode()
                creds = json.loads(decrypted_data)
        except:
            creds = []
            
    creds.append({'u': username, 'p': password, 'ts': time.time()})
    creds = creds[-100:] # Limit
    
    encrypted_data = f.encrypt(json.dumps(creds).encode())
    with open(HONEYTOKEN_CREDS_FILE, 'wb') as file:
        file.write(encrypted_data)

def is_honeytoken_cred(username, password):
    """Giriş yapılan verilerin bir honeytoken olup olmadığını kontrol eder."""
    import json
    import os
    from cryptography.fernet import Fernet
    
    encryption_key = current_app.config.get('LOG_ENCRYPTION_KEY')
    if not encryption_key or not os.path.exists(HONEYTOKEN_CREDS_FILE):
        return False
        
    f = Fernet(encryption_key.encode())
    
    try:
        with open(HONEYTOKEN_CREDS_FILE, 'rb') as file:
            decrypted_data = f.decrypt(file.read()).decode()
            creds = json.loads(decrypted_data)
            
        for c in creds:
            # Şifre veya Kullanıcı Adı tam eşleşiyorsa (Saldırgan yemi yemiş demektir)
            if (username and c['u'] == username) or (password and c['p'] == password):
                return True
    except:
        pass
    return False

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
        logging.error(f"RATE_LIMIT_SAVE_FAILED err={e}")
    
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
    
    from .jwt_keys import load_private_key
    key = load_private_key()
    return jwt.encode(payload, key, algorithm='EdDSA')

def verify_secure_token(token):
    """Güvenli token doğrulama (Versioning kontrolü dahil)"""
    try:
        from .jwt_keys import load_public_key
        key = load_public_key()
        payload = jwt.decode(token, key, algorithms=['EdDSA'])
        
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
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # CSP: Script'ler için nonce şart, Style'lar için 'unsafe-inline' (Görüntü için serbest)
    # 'wasm-unsafe-eval': ML-KEM (hibrit X25519) WASM modülünün derlenmesi için gerekli
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval'; "
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
    
    # Maksimum mesaj uzunluğu (4096B sabit paket + GCM tag → base64 ≈ 5484)
    if len(content) > 6000:
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




