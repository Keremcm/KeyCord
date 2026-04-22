from flask import request, g, session, current_app
from functools import wraps
import time
from .security import (
    rate_limit_check, log_security_event, add_security_headers,
    generate_csrf_token, check_login_attempts, record_failed_login,
    clear_failed_login_attempts, sanitize_input, get_remote_addr
)

def security_middleware(app):
    """Ana güvenlik middleware'i"""
    
    @app.before_request
    def before_request():
        # Rate limiting kontrolü
        identifier = get_remote_addr()
        if not rate_limit_check(identifier):
            print(f"DEBUG: security_middleware rate_limit_check FAILED for {identifier}")
            log_security_event('RATE_LIMIT_EXCEEDED', f'IP: {identifier}')
            return {'error': 'Çok fazla istek. Lütfen bekleyin.'}, 429
        
        # CSRF token oluştur
        if 'csrf_token' not in session:
            generate_csrf_token()
        
        # Güvenlik logları
        if request.method in ['POST', 'PUT', 'DELETE']:
            log_security_event('REQUEST', f'{request.method} {request.path}', 
                             user_id=session.get('user_id'))
        
        # Session timeout kontrolü
        if 'user_id' in session:
            last_activity = session.get('last_activity', 0)
            current_time = time.time()
            if current_time - last_activity > 3600:  # 1 saat
                session.clear()
                log_security_event('SESSION_TIMEOUT', f'User: {session.get("user_id")}')
            else:
                session['last_activity'] = current_time
    
    @app.after_request
    def after_request(response):
        # Güvenlik header'larını ekle
        response = add_security_headers(response)

        # CORS header'ları — Whitelist tabanlı, wildcard '*' yasak
        allowed_origins = current_app.config.get(
            'ALLOWED_ORIGINS',
            ['http://127.0.0.1:8005', 'http://localhost:8005']
        )
        origin = request.headers.get('Origin', '')
        if origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Vary'] = 'Origin'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-CSRF-Token, X-Requested-With'

        return response
    
    @app.errorhandler(404)
    def not_found(error):
        log_security_event('404_ERROR', f'Path: {request.path}')
        return {'error': 'Sayfa bulunamadı.'}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        log_security_event('500_ERROR', f'Path: {request.path}')
        return {'error': 'Sunucu hatası.'}, 500

def login_security_middleware(app):
    """Giriş güvenlik middleware'i"""
    
    @app.before_request
    def check_login_security():
        if request.endpoint in ['auth.login_page', 'auth.register']:
            identifier = get_remote_addr()
            
            # Login attempt kontrolü
            if not check_login_attempts(identifier):
                log_security_event('LOGIN_LOCKOUT', f'IP: {identifier}')
                return {'error': 'Çok fazla başarısız giriş denemesi. Lütfen 5 dakika bekleyin.'}, 429

def input_sanitization_middleware(app):
    """Input sanitization middleware'i"""
    
    @app.before_request
    def sanitize_inputs():
        if request.method in ['POST', 'PUT']:
            # Form data sanitization (verify-human hariç)
            if request.form and request.path != '/api/verify-human':
                for key, value in request.form.items():
                    if isinstance(value, str):
                        sanitized = sanitize_input(value)
                        if sanitized is None:
                            print(f"DEBUG: input_sanitization_middleware form sanitization FAILED for {key}")
                            log_security_event('MALICIOUS_INPUT', f'Field: {key}, Value: {value[:50]}')
                            return {'error': 'Geçersiz input tespit edildi.'}, 400
                        # request.form[key] = sanitized  # Bu satırı kaldırdık
            
            # JSON data sanitization
            if request.is_json and request.path != '/api/verify-human':
                data = request.get_json(silent=True)
                if data:
                    sanitized_data = sanitize_json_data(data)
                    if sanitized_data is None:
                        print(f"DEBUG: input_sanitization_middleware JSON sanitization FAILED")
                        log_security_event('MALICIOUS_JSON', f'Data: {str(data)[:100]}')
                        return {'error': 'Geçersiz JSON data tespit edildi.'}, 400
                    # request._json = sanitized_data  # Bu satırı da kaldırdık

def sanitize_json_data(data):
    """JSON data sanitization"""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized_value = sanitize_input(value)
                if sanitized_value is None:
                    return None
                sanitized[key] = sanitized_value
            elif isinstance(value, (dict, list)):
                sanitized_value = sanitize_json_data(value)
                if sanitized_value is None:
                    return None
                sanitized[key] = sanitized_value
            else:
                sanitized[key] = value
        return sanitized
    elif isinstance(data, list):
        sanitized = []
        for item in data:
            if isinstance(item, str):
                sanitized_item = sanitize_input(item)
                if sanitized_item is None:
                    return None
                sanitized.append(sanitized_item)
            elif isinstance(item, (dict, list)):
                sanitized_item = sanitize_json_data(item)
                if sanitized_item is None:
                    return None
                sanitized.append(sanitized_item)
            else:
                sanitized.append(item)
        return sanitized
    else:
        return data

def session_security_middleware(app):
    """Session güvenlik middleware'i"""
    
    @app.before_request
    def check_session_security():
        if 'user_id' in session:
            # Session hijacking kontrolü
            user_agent = request.headers.get('User-Agent', '')
            stored_agent = session.get('user_agent')
            
            if stored_agent and stored_agent != user_agent:
                log_security_event('SESSION_HIJACKING_ATTEMPT', 
                                 f'User: {session.get("user_id")}, Stored: {stored_agent}, Current: {user_agent}')
                session.clear()
                return {'error': 'Güvenlik ihlali tespit edildi.'}, 401
            
            # IP değişikliği kontrolü
            stored_ip = session.get('ip_address')
            current_ip = get_remote_addr()
            
            if stored_ip and stored_ip != current_ip:
                log_security_event('IP_CHANGE', 
                                 f'User: {session.get("user_id")}, Old: {stored_ip}, New: {current_ip}')
                # IP değişikliğinde session'ı yenile
                session['ip_address'] = current_ip

def file_upload_security_middleware(app):
    """Dosya yükleme güvenlik middleware'i"""
    
    @app.before_request
    def check_file_upload():
        if request.method == 'POST' and request.files:
            for file_key, file_obj in request.files.items():
                if file_obj and file_obj.filename:
                    # Dosya türü kontrolü
                    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
                    file_ext = file_obj.filename.rsplit('.', 1)[1].lower() if '.' in file_obj.filename else ''
                    
                    if file_ext not in allowed_extensions:
                        log_security_event('INVALID_FILE_UPLOAD', 
                                         f'File: {file_obj.filename}, User: {session.get("user_id")}')
                        return {'error': 'Geçersiz dosya türü.'}, 400
                    
                    # Dosya boyutu kontrolü (5MB)
                    file_obj.seek(0, 2)  # Dosyanın sonuna git
                    file_size = file_obj.tell()
                    file_obj.seek(0)  # Başa dön
                    
                    if file_size > 5 * 1024 * 1024:  # 5MB
                        log_security_event('LARGE_FILE_UPLOAD', 
                                         f'File: {file_obj.filename}, Size: {file_size}, User: {session.get("user_id")}')
                        return {'error': 'Dosya boyutu çok büyük.'}, 400

def api_security_middleware(app):
    """API güvenlik middleware'i"""
    
    @app.before_request
    def check_api_security():
        if request.path.startswith('/api/'):
            # API rate limiting (daha sıkı)
            client_ip = get_remote_addr()
            identifier = f"api_{client_ip}"
            if not rate_limit_check(identifier, max_requests=60, window=60):  # eski: 1000
                log_security_event('API_RATE_LIMIT', f'IP: {client_ip}')
                return {'error': 'API rate limit aşıldı.'}, 429
            
            # API authentication kontrolü (verify-human hariç)
            if request.method in ['POST', 'PUT', 'DELETE'] and request.path != '/api/verify-human':
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    log_security_event('API_NO_AUTH', f'Path: {request.path}')
                    return {'error': 'API authentication gerekli.'}, 401

def socket_security_middleware(socketio):
    """Socket.IO güvenlik middleware'i"""
    
    @socketio.on('connect')
    def handle_connect():
        # Socket bağlantı güvenlik kontrolü
        client_ip = get_remote_addr()
        log_security_event('SOCKET_CONNECT', f'IP: {client_ip}')
        
        # Rate limiting kontrolü
        identifier = f"socket_connect_{client_ip}"
        if not rate_limit_check(identifier, max_requests=20, window=60):  # eski: 200
            log_security_event('SOCKET_RATE_LIMIT', f'IP: {client_ip}')
            return False  # Bağlantıyı reddet
    
    @socketio.on('disconnect')
    def handle_disconnect():
        client_ip = get_remote_addr()
        log_security_event('SOCKET_DISCONNECT', f'IP: {client_ip}')

def apply_all_middleware(app, socketio):
    """Tüm middleware'leri uygula"""
    security_middleware(app)
    login_security_middleware(app)
    input_sanitization_middleware(app)
    session_security_middleware(app)
    file_upload_security_middleware(app)
    api_security_middleware(app)
    socket_security_middleware(socketio)