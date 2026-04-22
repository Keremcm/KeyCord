from flask import Blueprint, request, jsonify, current_app
from app import db
from app.models import User, ChatMessage
from app.security import require_auth, rate_limit_check, log_security_event, check_login_attempts, record_failed_login, clear_failed_login_attempts
import time

app_api_bp = Blueprint('app_api', __name__, url_prefix='/api/app/v1')

@app_api_bp.route('/status', methods=['GET'])
def status():
    return jsonify({"status": "KeyCord App API v1 is active", "version": "1.0.0"})

@app_api_bp.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr

    # Brute-force koruması — ana login endpoint'i ile aynı mekanizma
    if not check_login_attempts(ip):
        log_security_event('API_LOGIN_LOCKOUT', f'IP: {ip}')
        return jsonify({"error": "Çok fazla başarısız giriş denemesi. Lütfen 5 dakika bekleyin."}), 429

    data = request.get_json(silent=True) or {}
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        record_failed_login(ip)
        return jsonify({"error": "Email ve şifre gerekli."}), 400

    user = User.query.filter_by(email=email).first()
    from app.utils import check_password, generate_token

    if user and check_password(password, user.password):
        if not user.is_verified:
            return jsonify({"error": "Hesap doğrulanmamış."}), 403

        # Başarılı giriş — sayıcı sıfırla
        clear_failed_login_attempts(ip)
        log_security_event('API_LOGIN_SUCCESS', f'User: {user.username}, IP: {ip}')

        token = generate_token(user.id)
        return jsonify({
            "success": True,
            "token": token,
            "user_id": user.id,
            "username": user.username,
            "public_key": user.public_key,
            "encrypted_private_key": user.encrypted_private_key,
            "salt": user.salt,
            "key_type": 'X25519' if user.public_key and len(user.public_key) < 100 else 'RSA'
        })

    # Başarısız giriş — sayıcı artır
    record_failed_login(ip)
    log_security_event('API_LOGIN_FAILED', f'Email: {email}, IP: {ip}')
    return jsonify({"error": "Geçersiz giriş bilgileri."}), 401

@app_api_bp.route('/update_keys', methods=['POST'])
@require_auth
def update_keys():
    user_id = g.user_id
    user = User.query.get(user_id)
    data = request.get_json(silent=True) or {}
    
    user.public_key = data.get('public_key')
    user.encrypted_private_key = data.get('encrypted_private_key')
    user.salt = data.get('salt')
    
    db.session.commit()
    log_security_event('KEYS_UPDATED_VIA_APP', f'User: {user.username}')
    
    return jsonify({"success": True, "message": "Keys updated successfully"})

@app_api_bp.route('/get_public_key/<int:user_id>', methods=['GET'])
def get_public_key(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "public_key": user.public_key,
        "key_type": 'X25519' if user.public_key and len(user.public_key) < 100 else 'RSA'
    })

# Additional secure routes for messages, etc.
