# Jinja2 filter for datetime formatting
import datetime
from flask import Flask
from .models import (
    User, FriendRequest, Friendship, ChatMessage, Notification, 
    Announcement, BlockedUser, Group, 
    Community, CommunityMessage, RememberToken
)
from flask import Blueprint, request, render_template, redirect, url_for, flash, session, make_response, current_app, g, jsonify, abort, send_from_directory
from app import db, socketio
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import re
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from .utils import hash_password, check_password, generate_token, verify_token, get_conversation, save_message

class LoginRSA:
    _private_key = None
    public_key_pem = ""

    @classmethod
    def _initialize(cls):
        if cls._private_key:
            return
        
        # current_app can only be accessed within a request context
        key_path = os.path.join(current_app.instance_path, 'login_rsa.pem')
        os.makedirs(current_app.instance_path, exist_ok=True)
        
        if os.path.exists(key_path):
            try:
                with open(key_path, 'rb') as f:
                    key = RSA.import_key(f.read())
            except Exception as e:
                print(f"RSA Load Error: {e}")
                key = RSA.generate(2048)
                with open(key_path, 'wb') as f:
                    f.write(key.export_key('PEM'))
        else:
            key = RSA.generate(2048)
            with open(key_path, 'wb') as f:
                f.write(key.export_key('PEM'))

        cls._private_key = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        cls.public_key_pem = key.publickey().export_key('PEM').decode('utf-8')

    @classmethod
    def decrypt(cls, encrypted_b64):
        cls._initialize()
        if not cls._private_key:
            return encrypted_b64
        try:
            enc_data = base64.b64decode(encrypted_b64)
            return cls._private_key.decrypt(enc_data).decode('utf-8')
        except Exception as e:
            print(f"Decryption failed: {e}")
            return encrypted_b64

from .utils import generate_remember_token, verify_remember_token, delete_remember_token, delete_user_remember_tokens
from .utils import create_group, add_user_to_group, get_user_groups, save_group_message, get_group_messages
import os
import uuid
from flask_socketio import emit, join_room
from .security import (
    require_auth, require_csrf, generate_csrf_token, validate_password_strength,
    validate_username, validate_email, sanitize_input, log_security_event,
    record_failed_login, clear_failed_login_attempts, check_login_attempts,
    validate_file_upload, generate_secure_token, verify_secure_token,
    rate_limit_check, validate_user_input, sanitize_message_content,
    validate_friendship, verify_turnstile, get_remote_addr,
    is_malicious_request, check_ban_cookie,
    load_banned_ips, save_banned_ip
)
import time
import logging
import random
import string
import marshmallow as ma
import mimetypes
import subprocess
import shutil

auth_bp = Blueprint("auth", __name__)
main_bp = Blueprint("main", __name__)

@auth_bp.context_processor
def inject_user():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        # Fetch friends and groups for the sidebar
        friends = User.query.join(Friendship, Friendship.friend_id == User.id)\
            .filter(Friendship.user_id == user_id).all()
        groups = get_user_groups(user_id)
        
        # Fetch joined communities
        from .models import Community
        all_communities = Community.query.all()
        my_communities = [c for c in all_communities if user_id in c.members]
        
        return dict(current_user=user, friends=friends, groups=groups, my_communities=my_communities)
    return dict(current_user=None, friends=[], groups=[], my_communities=[])

@auth_bp.app_template_filter('avatar_url')
def avatar_url_filter(name):
    """Jinja2 filter to generate local avatar URL"""
    from flask import url_for
    return url_for('auth.generate_avatar', name=name or 'User')


LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "actions.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

def log_action(event, user=None, ip=None, target=None, extra=None):
    msg = f"{event} | user={user} | ip={ip} | target={target} | {extra or ''}"
    logging.info(msg)

# --- GLOBAL RATE LIMITING (DoS/DDOS) ---
GLOBAL_RATE_LIMITS = {}  # {ip: [timestamps]}
GLOBAL_RATE_LIMIT_WINDOW = 60  # saniye
GLOBAL_RATE_LIMIT_MAX = 400    # 1 dakikada 400 istek (eski: 10.000 — çok yüksekti)

def is_global_rate_limited(ip, max_req=GLOBAL_RATE_LIMIT_MAX, window=GLOBAL_RATE_LIMIT_WINDOW):
    now = time.time()
    timestamps = GLOBAL_RATE_LIMITS.get(ip, [])
    timestamps = [t for t in timestamps if now - t < window]
    if len(timestamps) >= max_req:
        log_action("RATE_LIMIT_BLOCK", user=None, ip=ip, extra=f"limit={max_req}/{window}s")
        return True
    timestamps.append(now)
    GLOBAL_RATE_LIMITS[ip] = timestamps
    return False

@auth_bp.before_app_request
def global_rate_limit():
    ip = get_remote_addr()
    if is_global_rate_limited(ip):
        log_action("DDOS_BLOCKED", user=None, ip=ip, extra="Global rate limit aşıldı")
        abort(429, "Çok fazla istek. Lütfen bekleyin.")

# --- BRUTE FORCE KORUMASI (login/register) ---
LOGIN_ATTEMPTS = {}  # {ip: [timestamps]}
LOGIN_WINDOW = 300  # 5 dakika
LOGIN_MAX = 10      # 5 dakikada 10 deneme (eski: 100 — brute-force'a karşı yetersizdi)

def is_login_limited(ip):
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW]
    if len(attempts) >= LOGIN_MAX:
        log_action("BRUTE_FORCE_BLOCK", user=None, ip=ip, extra=f"login_fail={LOGIN_MAX}/{LOGIN_WINDOW}s")
        return True
    LOGIN_ATTEMPTS[ip] = attempts
    return False

REGISTER_ATTEMPTS = {}  # {ip: [timestamps]}
REGISTER_WINDOW = 300
REGISTER_MAX = 5  # 5 dakikada 5 kayıt (eski: 100)

def is_register_limited(ip):
    now = time.time()
    attempts = REGISTER_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < REGISTER_WINDOW]
    if len(attempts) >= REGISTER_MAX:
        log_action("REGISTER_DOS_BLOCK", user=None, ip=ip, extra=f"register_fail={REGISTER_MAX}/{REGISTER_WINDOW}s")
        return True
    REGISTER_ATTEMPTS[ip] = attempts
    return False

# 5. Kapsamlı input validation için örnek Marshmallow şeması:
class RegisterSchema(ma.Schema):
    username = ma.fields.Str(required=True, validate=ma.validate.Length(min=3, max=20))
    email = ma.fields.Email(required=True)
    password = ma.fields.Str(required=True, validate=ma.validate.Length(min=8))
    confirm_password = ma.fields.Str(required=True)

register_schema = RegisterSchema()

# 7. Tüm yanıtlara güvenlik header'ı ekle
@auth_bp.after_app_request
def set_security_headers(response):
    for k, v in current_app.config.get("SECURITY_HEADERS", {}).items():
        response.headers[k] = v
    return response

# 8. Dosya yükleme güvenliği (MIME type ve uzantı kontrolü)
def allowed_file(filename, fileobj=None):
    """Güvenli dosya yükleme kontrolü"""
    if not filename:
        return False
    
    # İzin verilen dosya uzantıları
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}
    
    # Dosya uzantısını al
    if '.' not in filename:
        return False
    
    extension = filename.rsplit('.', 1)[1].lower()
    
    # Uzantı kontrolü
    if extension not in ALLOWED_EXTENSIONS:
        return False
    
    # Dosya boyutu kontrolü (5MB)
    if fileobj:
        try:
            # Dosya boyutunu kontrol et
            fileobj.seek(0, 2)  # Dosyanın sonuna git
            file_size = fileobj.tell()  # Boyutu al
            fileobj.seek(0)  # Başa dön
            
            MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
            if file_size > MAX_FILE_SIZE:
                print(f"DEBUG: File too large: {file_size} bytes")
                return False
            
            print(f"DEBUG: File size OK: {file_size} bytes")
        except Exception as e:
            print(f"DEBUG: Error checking file size: {e}")
    
    return True

# 9. IP engelleme (örnek: kara liste)
BLOCKED_IPS = load_banned_ips()
TEMP_BLOCKED_IPS = {} # ip -> expiry_timestamp
@auth_bp.before_app_request
def block_bad_ips():
    ip = get_remote_addr()
    
    # KRİTİK: Zararlı pattern kontrolü IP'den BAĞIMSIZ yapılmalı.
    # Lokal IP gibi görünse bile saldırı kodu varsa engelle.
    if is_malicious_request(request.url) or is_malicious_request(request.get_data(as_text=True)):
        if ip and not ip.startswith("127."):
            if ip not in BLOCKED_IPS:
                BLOCKED_IPS.add(ip)
                save_banned_ip(ip)
        log_security_event('MALICIOUS_REQUEST_PERMANENT_BAN', f'IP: {ip}, URL: {request.url}')
        abort(403, "Kritik güvenlik ihlali tespit edildi.")

    if ip.startswith("127.") or ip.startswith("192.168."):
        return  # Temiz lokal IP'leri engelleme
        
    # Geçici Ban Kontrolü (Honeypot kaynaklı)
    temp_expiry = TEMP_BLOCKED_IPS.get(ip)
    if temp_expiry and time.time() < temp_expiry:
        diff = int(temp_expiry - time.time())
        abort(403, f"Çok fazla hatalı istek. Erişiminiz {diff} saniye daha kısıtlıdır.")

    # IP veya Çerez tabanlı ban kontrolü
    if ip in BLOCKED_IPS or check_ban_cookie():
        log_action("BANNED_IP_ATTEMPT", user=None, ip=ip)
        abort(403, "Bu servise erişiminiz kalıcı olarak engellendi.")

# 4. E-posta doğrulama için kayıt sonrası e-posta gönderimi (örnek, gerçek gönderim için Flask-Mail gerekir)
# Local Avatar Generator Route
@auth_bp.route('/avatar/<name>')
def generate_avatar(name):
    """Generate SVG avatar locally instead of using ui-avatars.com"""
    from .avatar_generator import avatar_response
    size = request.args.get('size', 128, type=int)
    return avatar_response(name, size)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        ip = get_remote_addr()
        if is_register_limited(ip):
            flash('Çok fazla kayıt denemesi. Lütfen 5 dakika bekleyin.')
            return redirect(url_for('auth.register'))
            
        REGISTER_ATTEMPTS[ip].append(time.time())
        # Rate limiting kontrolü
        if not rate_limit_check(f"register_{get_remote_addr()}", 5, 300):
            flash('Çok fazla kayıt denemesi. Lütfen 5 dakika bekleyin.')
            return redirect(url_for('auth.register'))
        
        # Cloudflare Turnstile doğrulama
        turnstile_token = request.form.get('cf-turnstile-response')
        if not verify_turnstile(turnstile_token):
            flash('Lütfen insan olduğunuzu doğrulayın.')
            return redirect(url_for('auth.register'))
        
        # Input validasyonu ve sanitization
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Input sanitization
        username = sanitize_input(username)
        email = sanitize_input(email)
        
        if username is None or email is None:
            flash('Geçersiz karakterler tespit edildi.')
            return redirect(url_for('auth.register'))
        
        # Kullanıcı adı validasyonu
        is_valid_username, username_error = validate_username(username)
        if not is_valid_username:
            flash(username_error)
            return redirect(url_for('auth.register'))
        
        # Email validasyonu
        is_valid_email, email_error = validate_email(email)
        if not is_valid_email:
            flash(email_error)
            return redirect(url_for('auth.register'))
        
        # Şifre gücü kontrolü
        is_strong_password, password_error = validate_password_strength(password)
        if not is_strong_password:
            flash(password_error)
            return redirect(url_for('auth.register'))
        
        # Şifre eşleşme kontrolü
        if password != confirm_password:
            flash('Şifreler uyuşmuyor.')
            return redirect(url_for('auth.register'))
        
        # Kullanıcı adı benzersizlik kontrolü
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten alınmış.')
            return redirect(url_for('auth.register'))
        
        # Email benzersizlik kontrolü
        if User.query.filter_by(email=email).first():
            flash('Bu email zaten kayıtlı.')
            return redirect(url_for('auth.register'))
        
        # Kullanıcı oluştur
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            # E2EE Keys
            public_key=request.form.get('public_key'),
            encrypted_private_key=request.form.get('encrypted_private_key'),
            salt=request.form.get('salt')
        )
        db.session.add(new_user)
        db.session.commit()
        log_action("REGISTER", user=username, ip=get_remote_addr())
        
        # Güvenlik logu
        log_security_event('USER_REGISTERED', f'Username: {username}, Email: {email}')
        
        # 4. İnsan doğrulama adımına yönlendir
        session['pending_verification_user_id'] = new_user.id
        
        return redirect(url_for('auth.human_verification'))
    
    return render_template('register.html', csrf_token=generate_csrf_token())

@auth_bp.route('/human-verification')
def human_verification():
    """İnsan doğrulama (10 saniye basılı tutma) sayfası"""
    user_id = session.get('pending_verification_user_id')
    if not user_id:
        return redirect(url_for('auth.register'))
        
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('auth.register'))
        
    if user.is_verified:
        return redirect(url_for('auth.login_page'))
        
    return render_template('human_verification.html', user=user, csrf_token=generate_csrf_token())

@auth_bp.route('/api/verify-human', methods=['POST'])
def verify_human_api():
    """İnsan doğrulama işlemini tamamlayan API endpoint'i"""
    # Manuel CSRF kontrolü (Hem form hem header destekler)
    csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    session_token = session.get('csrf_token')
    
    if not csrf_token or not session_token or csrf_token != session_token:
        print(f"DEBUG: verify_human_api CSRF FAILED. Received: {csrf_token}, Session: {session_token}")
        log_security_event('CSRF_ATTEMPT', f'Route: verify_human_api')
        return jsonify({"error": "Güvenlik doğrulaması başarısız (CSRF)."}), 403

    user_id = session.get('pending_verification_user_id')
    if not user_id:
        return jsonify({"error": "Oturum geçersiz veya süresi dolmuş."}), 401
        
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Kullanıcı bulunamadı."}), 404
        
    # JSON verisini güvenli bir şekilde almaya çalış
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}

    # Cloudflare Turnstile doğrulama
    turnstile_token = request.form.get('cf-turnstile-response')
    if not verify_turnstile(turnstile_token):
        return jsonify({"error": "Lütfen insan olduğunuzu doğrulayın (Turnstile)."}), 400

    # Güvenlik Logu
    log_security_event('HUMAN_VERIFICATION_COMPLETE', f'Username: {user.username}')
    
    # Kullanıcıyı doğrulanmış olarak işaretle
    user.is_verified = True
    db.session.commit()
    
    # Geçici session verisini temizle
    session.pop('pending_verification_user_id', None)
    
    flash('İnsan olduğunuz doğrulandı! Hoş geldiniz.', 'success')
    return jsonify({
        "success": True, 
        "redirect": url_for('auth.login_page')
    })

@auth_bp.route("/me", methods=["GET"])
def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Yetkilendirme tokenı eksik."}), 401

    token = auth_header.split(" ")[1]
    user_id = verify_token(token)

    if not user_id:
        return jsonify({"error": "Geçersiz veya süresi dolmuş token."}), 401

    user = User.query.get(user_id)
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    }), 200
    
@auth_bp.route("/me", methods=["PUT"])
def update_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Yetkilendirme tokenı eksik."}), 401

    token = auth_header.split(" ")[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({"error": "Geçersiz token."}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Kullanıcı bulunamadı."}), 404

    data = request.get_json(silent=True) or {}

    new_username = data.get("username")
    new_email = data.get("email")
    new_password = data.get("password")

    # Şifre değiştirme işlemi: mevcut şifre zorunlu
    if new_password:
        current_password = data.get("current_password")
        if not current_password:
            return jsonify({"error": "Şifre değiştirmek için mevcut şifrenizi girmelisiniz."}), 400
        if not check_password(current_password, user.password):
            record_failed_login(get_remote_addr())
            log_security_event('PASSWORD_CHANGE_FAILED', f'User: {user.username}, IP: {get_remote_addr()}')
            return jsonify({"error": "Mevcut şifre yanlış."}), 403
        user.password = hash_password(new_password)
        log_security_event('PASSWORD_CHANGED', f'User: {user.username}')

    if new_username:
        # Kullanıcı adı benzersizlik kontrolü
        exists = User.query.filter(User.username == new_username, User.id != user_id).first()
        if exists:
            return jsonify({"error": "Bu kullanıcı adı zaten alınmış."}), 409
        user.username = new_username

    if new_email:
        # E-posta benzersizlik kontrolü
        exists = User.query.filter(User.email == new_email, User.id != user_id).first()
        if exists:
            return jsonify({"error": "Bu e-posta adresi zaten kayıtlı."}), 409
        user.email = new_email

    db.session.commit()
    log_security_event('USER_UPDATED', f'User: {user.username}')
    return jsonify({"message": "Bilgiler güncellendi."}), 200

@auth_bp.route('/add-friend', methods=['POST'])
def add_friend():
    user_id = session.get('user_id')
    
    # If not in session, check for Bearer Token
    if not user_id:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            user_id = verify_token(token)

    if not user_id:
        if request.headers.get("Authorization"): # API request
            return jsonify({"error": "Token geçersiz veya gerekli."}), 401
        else: # Form post
            flash('Giriş yapmalısınız.', 'error')
            return redirect(url_for('auth.login_page'))

    # Retrieve data from JSON or Form
    if request.is_json:
        data = request.get_json(silent=True)
        friend_username = data.get("username")
    else:
        friend_username = request.form.get("username")

    if not friend_username:
        if request.is_json:
            return jsonify({"error": "Kullanıcı adı gerekli."}), 400
        else:
            flash('Kullanıcı adı gerekli.', 'error')
            return redirect(url_for('auth.add_friend_page'))

    friend = User.query.filter_by(username=friend_username).first()

    if not friend:
        if request.is_json:
            return jsonify({"error": "Kullanıcı bulunamadı."}), 404
        else:
            flash('Kullanıcı bulunamadı.', 'error')
            return redirect(url_for('auth.add_friend_page'))

    if friend.id == user_id:
        if request.is_json:
            return jsonify({"error": "Kendini ekleyemezsin."}), 400
        else:
            flash('Kendinizi ekleyemezsiniz.', 'warning')
            return redirect(url_for('auth.add_friend_page'))

    existing = Friendship.query.filter_by(user_id=user_id, friend_id=friend.id).first()
    if existing:
        if request.is_json:
            return jsonify({"error": "Zaten arkadaşsınız."}), 400
        else:
            flash('Zaten arkadaşsınız.', 'warning')
            return redirect(url_for('auth.add_friend_page'))

    friendship = Friendship(user_id=user_id, friend_id=friend.id)
    reverse = Friendship(user_id=friend.id, friend_id=user_id)
    db.session.add(friendship)
    db.session.add(reverse)
    
    # Create notification for target user
    notif = Notification(user_id=friend.id, type='friend_accepted', from_user_id=user_id)
    db.session.add(notif)
    
    db.session.commit()
    log_action("ADD_FRIEND", user=user_id, ip=get_remote_addr(), target=friend_username)

    if request.is_json:
        return jsonify({"message": f"{friend.username} başarıyla eklendi."}), 201
    else:
        flash(f'{friend.username} başarıyla eklendi.', 'success')
        return redirect(url_for('auth.add_friend_page'))

@auth_bp.route('/')
def welcome():
    """Hoşgeldiniz sayfası - İlk giriş"""
    user_id = session.get('user_id')
    if user_id:
        # Kullanıcı zaten giriş yapmışsa ana sayfaya yönlendir
        return redirect(url_for('auth.dashboard'))
    
    # Cookie kontrolü
    remember_token = request.cookies.get('remember_token')
    if remember_token:
        user_id = verify_remember_token(remember_token)
        if user_id:
            session['user_id'] = user_id
            return redirect(url_for('auth.dashboard'))
    
    return render_template('welcome.html')

@auth_bp.route('/dashboard')
def dashboard():
    """Ana sayfa (eski home fonksiyonu)"""
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.welcome'))
    
    # Cookie kontrolü
    remember_token = request.cookies.get('remember_token')
    if not user_id and remember_token:
        user_id = verify_remember_token(remember_token)
        if user_id:
            session['user_id'] = user_id
    
    if not user_id:
        return redirect(url_for('auth.welcome'))
    
    user = User.query.get(user_id)
    friends_with_pics = []
    friends = User.query.join(Friendship, Friendship.friend_id == User.id)\
        .filter(Friendship.user_id == user_id).all()
    
    from .models import ChatMessage
    import datetime
    
    for f in friends:
        last_msg = ChatMessage.query.filter(
            ((ChatMessage.sender_id == user_id) & (ChatMessage.receiver_id == f.id)) |
            ((ChatMessage.sender_id == f.id) & (ChatMessage.receiver_id == user_id))
        ).order_by(ChatMessage.timestamp.desc()).first()
        
        last_time = last_msg.timestamp if last_msg else datetime.datetime.min
        
        friends_with_pics.append({
            'id': f.id,
            'username': f.username,
            'profile_pic': f.profile_pic,
            'profile_frame': f.profile_frame or 'none',
            'last_interaction': last_time
        })
        
    # Sort by recent interaction
    friends_with_pics.sort(key=lambda x: x['last_interaction'], reverse=True)
    
    # Bildirimler
    notifications = Notification.query.filter_by(user_id=user_id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notif_data = []

    for n in notifications:
        if n.type == 'friend_request':
            from_user = User.query.get(n.from_user_id) if n.from_user_id else None
            if from_user:
                notif_data.append({
                    'id': n.id,
                    'type': n.type,
                    'from_user_username': from_user.username,
                    'from_user_id': from_user.id
                })
        elif n.type == 'message':
            from_user = User.query.get(n.from_user_id) if n.from_user_id else None
            if from_user:
                notif_data.append({
                    'id': n.id,
                    'type': n.type,
                    'from_user_username': from_user.username,
                    'from_user_id': from_user.id
                })

    # Token oluştur
    token = generate_token(user_id)
    
    # Grup listesi
    groups = get_user_groups(user_id)
    
    # Kullanıcının katıldığı topluluklar
    from .models import Community
    communities = Community.query.filter(Community.members.contains([user_id])).all()
    
    user_communities = []
    for comm in communities:
        user_communities.append({
            'id': comm.id,
            'name': comm.name,
            'description': comm.description,
            'avatar': comm.avatar,
            'is_owner': comm.owner_id == user_id,
            'member_count': len(comm.members)
        })
    
    return render_template('home.html', 
                         user=user, 
                         friends=friends_with_pics, 
                         notifications=notif_data,
                         token=token,
                         groups=groups,
                         communities=user_communities)

# home alias'ı ekle (geriye dönük uyumluluk için)
@auth_bp.route('/home')
def home():
    return redirect(url_for('auth.dashboard'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        ip = get_remote_addr()
        if is_login_limited(ip):
            flash('Çok fazla başarısız giriş denemesi. Lütfen 5 dakika bekleyin.')
            log_action("BRUTE_FORCE_BLOCK", user=None, ip=ip, extra="login brute force")
            if request.is_json:
                return jsonify({"error": "Çok fazla başarısız giriş denemesi. Lütfen 5 dakika bekleyin."}), 429
            return render_template('login.html', csrf_token=generate_csrf_token())
        
        if request.is_json:
            data = request.get_json(silent=True)
            email = data.get('email', '').strip()
            raw_password = data.get('password', '').strip()
            
            # Decrypt the client-side RSA encrypted password (or fallback to plaintext)
            password = LoginRSA.decrypt(raw_password)
            
            remember = data.get('remember', False)
        else:
            email = request.form.get('email', '').strip()
            raw_password = request.form.get('password', '').strip()
            password = LoginRSA.decrypt(raw_password)
            remember = request.form.get('remember') == 'on'
        
        # Input validasyonu
        if not email or not password:
            record_failed_login(ip)
            if request.is_json:
                return jsonify({"error": "Email ve şifre gerekli."}), 400
            flash('Email ve şifre gerekli.')
            return render_template('login.html', csrf_token=generate_csrf_token(), server_public_key=LoginRSA.public_key_pem)
        
        # Email format kontrolü
        is_valid_email, _ = validate_email(email)
        if not is_valid_email:
            record_failed_login(ip)
            if request.is_json:
                return jsonify({"error": "Geçersiz email formatı."}), 400
            flash('Geçersiz email formatı.')
            return render_template('login.html', csrf_token=generate_csrf_token(), server_public_key=LoginRSA.public_key_pem)
        
        user = User.query.filter_by(email=email).first()
        if user and check_password(password, user.password):
            # E-posta doğrulama kontrolü
            allow_unverified = current_app.config.get('ALLOW_UNVERIFIED_LOGIN', False)
            if not getattr(user, "is_verified", False) and not allow_unverified:
                if request.is_json:
                    return jsonify({"error": "Hesabınızı doğrulamadan giriş yapamazsınız."}), 403
                flash("Hesabınızı doğrulamadan giriş yapamazsınız.", "warning")
                return render_template('login.html', csrf_token=generate_csrf_token())
            # Başarılı giriş
            session['user_id'] = user.id
            session['user_agent'] = request.headers.get('User-Agent', '')
            session['ip_address'] = get_remote_addr()
            session['last_activity'] = time.time()
            
            # Başarısız giriş denemelerini temizle
            clear_failed_login_attempts(ip)
            
            # Güvenlik logu
            log_security_event('LOGIN_SUCCESS', f'User: {user.username}, Email: {email}')
            log_action("LOGIN_SUCCESS", user=user.username, ip=get_remote_addr())
            
            response_data = {
                "message": "Giriş başarılı.",
                "token": generate_secure_token(user.id),
                "username": user.username,
                # E2EE Keys
                "encrypted_private_key": user.encrypted_private_key,
                "salt": user.salt,
                "public_key": user.public_key
            }
            
            if request.is_json:
                response = jsonify(response_data)
            else:
                response = redirect(url_for('auth.home'))
            
            # Beni hatırla seçeneği işaretlendiyse çerez oluştur
            if remember:
                remember_token = generate_remember_token(user.id)
                response.set_cookie(
                    'remember_token', 
                    remember_token, 
                    max_age=30*24*60*60,  # 30 gün
                    httponly=True,
                    secure=True,  # HTTPS kullanıyorsanız True yapın
                    samesite='Lax'
                )
            
            return response
        else:
            # Başarısız giriş
            record_failed_login(ip)
            log_security_event('LOGIN_FAILED', f'Email: {email}, IP: {ip}')
            log_action("LOGIN_FAIL", user=email, ip=get_remote_addr())
            
            if request.is_json:
                return jsonify({"error": "Geçersiz giriş bilgileri."}), 401
            flash('Geçersiz giriş bilgileri.')
    
    return render_template('login.html', csrf_token=generate_csrf_token(), server_public_key=LoginRSA.public_key_pem)

@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        # Kullanıcının tüm çerez token'larını sil
        delete_user_remember_tokens(user_id)
    
    session.pop('user_id', None)
    response = make_response(render_template('logout.html'))
    response.delete_cookie('remember_token')
    return response

@auth_bp.route('/debug-locale')
def debug_locale():
    # Sadece oturum açmış kullanıcılara erişim izni
    user_id = session.get('user_id')
    if not user_id:
        log_security_event('UNAUTHORIZED_ACCESS', 'Route: debug_locale')
        return jsonify({"error": "Yetkilendirme gerekli."}), 401

    from app import get_locale
    locale = get_locale()
    # Hassas config bilgileri çıkarıldı, yalnızca locale devinfo döndürülüyor
    return jsonify({
        "detected_locale": str(locale),
    })


@auth_bp.route('/profile', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')
    if not user_id:
        # Çerez token'ını kontrol et
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
            else:
                response = make_response(redirect(url_for('auth.login_page')))
                response.delete_cookie('remember_token')
                return response
    
    if not user_id:
        return redirect(url_for('auth.login_page'))
    user = User.query.get(user_id)
    if request.method == 'POST':
        # Hakkında (Username değiştirilemez hale getirildi)
        user.about = request.form.get('about', '')

        # Profil Fotoğrafı Yükleme
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename != '' and allowed_file(file.filename, file):
                # Güvenli Dosya İşleme
                # Metadata stripping istemci (JavaScript/Canvas) tarafında yapılacak.
                # Sunucu tarafında sadece rastgele isim atayarak erişimi kısıtlıyoruz.
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{ext}"
                save_path = os.path.join(current_app.instance_path, 'profile_pics', filename)
                
                # Klasörün varlığından emin ol
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                
                file.save(save_path)

                # Eski fotoğrafı sil (eğer varsa ve default değilse)
                if user.profile_pic and user.profile_pic != 'default.png' and not user.profile_pic.startswith('http'):
                    try:
                        old_path = os.path.join(current_app.instance_path, 'profile_pics', user.profile_pic)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    except Exception as e:
                        print(f"Error deleting old profile pic: {e}")

                user.profile_pic = filename

        db.session.commit()
        flash('Profil güncellendi.')
    # Arkadaşlar
    friends = User.query.join(Friendship, Friendship.friend_id == User.id)\
        .filter(Friendship.user_id == user_id).all()
    return render_template('profile.html', user=user, friends=friends)

@auth_bp.route('/add-friend', methods=['GET', 'POST'])
def add_friend_page():
    user_id = session.get('user_id')
    if not user_id:
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
            else:
                response = make_response(redirect(url_for('auth.login_page')))
                response.delete_cookie('remember_token')
                return response
    if not user_id:
        return redirect(url_for('auth.login_page'))

    if request.method == 'POST':
        friend_username = request.form.get('username')
        friend = User.query.filter_by(username=friend_username).first()
        if not friend:
            flash('Kullanıcı bulunamadı.')
        elif friend.id == user_id:
            flash('Kendinizi ekleyemezsiniz.')
        elif Friendship.query.filter_by(user_id=user_id, friend_id=friend.id).first():
            flash('Zaten arkadaşsınız.')
        else:
            db.session.add(Friendship(user_id=user_id, friend_id=friend.id))
            db.session.add(Friendship(user_id=friend.id, friend_id=user_id))
            db.session.commit()
            flash(f'{friend.username} başarıyla eklendi.')

    # Arama işlevi
    search_query = request.args.get('search', '').strip()
    results = []
    
    if search_query:
        # Kendisi hariç ve arama terimini içeren kullanıcıları bul
        users = User.query.filter(User.username.ilike(f"%{search_query}%"), User.id != user_id).all()
        
        # Her kullanıcı için durum kontrolü yap
        for u in users:
            is_friend = Friendship.query.filter_by(user_id=user_id, friend_id=u.id).first() is not None
            request_sent = FriendRequest.query.filter_by(from_user_id=user_id, to_user_id=u.id, status='pending').first() is not None
            
            results.append({
                'id': u.id,
                'username': u.username,
                'profile_pic': u.profile_pic,
                'profile_frame': u.profile_frame or 'none',
                'is_friend': is_friend,
                'request_sent': request_sent
            })

    # Kullanıcının oyunlarını al (Öneriler için)
    # ... implementation omitted ...
    
    return render_template('add_friend.html', search_query=search_query, results=results)

@auth_bp.route('/api/search-users', methods=['GET'])
def search_users_api():
    """Anlık kullanıcı arama API'si"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    # Maksimum 20 sonuç döndür
    users = User.query.filter(User.username.ilike(f"%{query}%"), User.id != user_id).limit(20).all()
    
    results = []
    from flask import url_for
    
    for u in users:
        is_friend = Friendship.query.filter_by(user_id=user_id, friend_id=u.id).first() is not None
        request_sent = FriendRequest.query.filter_by(from_user_id=user_id, to_user_id=u.id, status='pending').first() is not None
        
        # Profil resmi URL'si
        profile_url = url_for('auth.serve_profile_picture', username=u.username)
        # Fallback avatar URL'si (ui-avatars vb veya local generator)
        avatar_fallback = url_for('auth.generate_avatar', name=u.username)

        results.append({
            'id': u.id,
            'username': u.username,
            'is_friend': is_friend,
            'request_sent': request_sent,
            'profile_url': profile_url,
            'avatar_fallback': avatar_fallback
        })
    
    return jsonify(results)
    user = User.query.get(user_id)
    user_games = set([g.strip().lower() for g in (user.games or '').split(',') if g.strip()])
    
    # Benzer oyunlara sahip kullanıcıları bul (arkadaş olmayanlar ve kendisi hariç)
    suggestions = []
    if user_games and not search_query: # Arama yapılıyorsa önerileri gösterme veya aşağıda göster
        all_users = User.query.filter(User.id != user_id).all()
        for u in all_users:
            if Friendship.query.filter_by(user_id=user_id, friend_id=u.id).first():
                continue
            u_games = set([g.strip().lower() for g in (u.games or '').split(',') if g.strip()])
            ortak = user_games & u_games
            if ortak:
                suggestions.append({
                    'id': u.id,
                    'username': u.username,
                    'profile_pic': u.profile_pic,
                    'profile_frame': u.profile_frame or 'none',
                    'about': u.about,
                    'games': u.games.split(',') if u.games else [],
                    'common_games': list(ortak)
                })

    return render_template('add_friend.html', suggestions=suggestions, results=results, search_query=search_query)

@auth_bp.route('/messages', methods=['GET'])
def messages():
    user_id = session.get('user_id')
    if not user_id:
        # Çerez token'ını kontrol et
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
            else:
                response = make_response(redirect(url_for('auth.login_page')))
                response.delete_cookie('remember_token')
                return response
    
    if not user_id:
        return redirect(url_for('auth.login_page'))

    # Bildirim okundu olarak işaretle (genel yöntemden ziyade kişi spesifik)
    notif_id = request.args.get("notif")
    selected = request.args.get("with")
    
    if notif_id:
        notif = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
        if notif:
            notif.is_read = True
            db.session.commit()
            
    if selected:
        # Sohbet açıldığında, o kişiden gelen tüm okunmamış mesaj bildirimlerini temizle
        unread_notifs = Notification.query.filter_by(
            user_id=user_id, 
            type='message', 
            from_user_id=selected,
            is_read=False
        ).all()
        if unread_notifs:
            for n in unread_notifs:
                n.is_read = True
            db.session.commit()

    friends = User.query.join(Friendship, Friendship.friend_id == User.id)\
        .filter(Friendship.user_id == user_id).all()
    user = User.query.get(user_id)
    selected = request.args.get("with")
    conversation = []
    selected_friend = None
    if selected:
        selected_friend = User.query.get(int(selected))
        # Veritabanından tüm sohbeti çek
        conversation_messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == user_id) & (ChatMessage.receiver_id == selected_friend.id)) |
            ((ChatMessage.sender_id == selected_friend.id) & (ChatMessage.receiver_id == user_id))
        ).order_by(ChatMessage.timestamp.asc()).all()
        
        # Şablon için formatla
        for msg in conversation_messages:
            sender_user = User.query.get(msg.sender_id)
            conversation.append({
                "sender": sender_user.username,
                "content": msg.content,
                "sender_profile_pic": sender_user.profile_pic,
                "sender_profile_frame": sender_user.profile_frame or 'none',
                "encrypted_aes_key": msg.encrypted_aes_key,
                "encrypted_aes_key_sender": msg.encrypted_aes_key_sender,
                "iv": msg.iv
            })

    token = generate_token(user_id)
    print("Message class:", ChatMessage)
    print("Message base:", getattr(ChatMessage, '__bases__', None))
    return render_template('messages.html', user=user, friends=friends, selected_friend=selected_friend, conversation=conversation, token=token)

@auth_bp.route('/send-message', methods=['POST'])
@require_auth
@require_csrf
def send_message():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Giriş yapmalısınız."}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Geçersiz veri."}), 400

    to_username = data.get("to", "").strip()
    content = data.get("content", "").strip()

    if not to_username or not content:
        return jsonify({"error": "Alıcı ve mesaj içeriği gerekli."}), 400

    user = User.query.get(user_id)
    friend = User.query.filter_by(username=to_username).first()

    if not friend:
        return jsonify({"error": "Kullanıcı bulunamadı."}), 404

    if not validate_friendship(user_id, friend.id):
        return jsonify({"error": "Arkadaş değilsiniz."}), 403

    encrypted_aes_key = data.get("encrypted_aes_key")
    iv = data.get("iv")

    save_message(user.id, friend.id, content, encrypted_aes_key, iv)
    notif = Notification(user_id=friend.id, type='message', from_user_id=user.id, related_id=user_id)
    db.session.add(notif)
    db.session.commit()

    socketio.emit('new_notification', {
        'type': 'message',
        'from_user_username': user.username,
        'url': url_for('auth.messages', _external=True) + f'?with={user.id}&notif={notif.id}'
    }, room=f'user_{friend.id}')

    return jsonify({"message": "Mesaj gönderildi."})

@auth_bp.route('/search-users')
def search_users():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify([])

    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])

    users = User.query.filter(User.username.ilike(f"%{q}%"), User.id != user_id).all()
    result = [{
        "id": u.id,
        "username": u.username,
        "profile_pic": u.profile_pic,
        "profile_frame": u.profile_frame or 'none',
        "about": u.about,
        "games": u.games.split(',') if u.games else []
    } for u in users]
    return jsonify(result)

@auth_bp.route('/send-friend-request', methods=['POST'])
def send_friend_request():
    user_id = session.get('user_id')
    if not user_id:
        if request.is_json:
            return jsonify({"error": "Giriş yapmalısınız."}), 401
        return redirect(url_for('auth.login_page'))

    # Parametreyi al (JSON, Form veya Query String)
    if request.is_json:
        to_user_id = request.json.get('to_user_id')
    else:
        to_user_id = request.form.get('to_user_id') or request.args.get('user_id')

    # to_user_id integer'a çevir
    try:
        if to_user_id:
            to_user_id = int(to_user_id)
    except ValueError:
        to_user_id = None

    if not to_user_id or to_user_id == user_id:
        if request.is_json:
            return jsonify({"error": "Geçersiz kullanıcı."}), 400
        flash("Geçersiz kullanıcı.", "error")
        return redirect(request.referrer or url_for('auth.add_friend_page'))

    # Engellenmiş mi? (İstisnai durum: Diğer taraf bizi engellemişse)
    if BlockedUser.query.filter_by(blocker_id=to_user_id, blocked_id=user_id).first():
        if request.is_json:
            return jsonify({"error": "Bu kullanıcıya istek gönderemezsiniz."}), 403
        flash("Bu kullanıcıya istek gönderemezsiniz.", "error")
        return redirect(request.referrer or url_for('auth.add_friend_page'))
    
    # Biz onu engellemiş miyiz?
    if BlockedUser.query.filter_by(blocker_id=user_id, blocked_id=to_user_id).first():
        if request.is_json:
            return jsonify({"error": "Önce bu kullanıcının engelini kaldırmalısınız."}), 400
        flash("Önce bu kullanıcının engelini kaldırmalısınız.", "warning")
        return redirect(request.referrer or url_for('auth.add_friend_page'))

    # Zaten arkadaş mı?
    if Friendship.query.filter_by(user_id=user_id, friend_id=to_user_id).first():
        if request.is_json:
            return jsonify({"error": "Zaten arkadaşsınız."}), 400
        flash("Zaten arkadaşsınız.", "warning")
        return redirect(request.referrer or url_for('auth.add_friend_page'))

    # Zaten istek atılmış mı?
    if FriendRequest.query.filter_by(from_user_id=user_id, to_user_id=to_user_id, status='pending').first():
        if request.is_json:
            return jsonify({"error": "Zaten istek attınız."}), 400
        flash("Zaten istek attınız.", "warning")
        return redirect(request.referrer or url_for('auth.add_friend_page'))

    fr = FriendRequest(from_user_id=user_id, to_user_id=to_user_id)
    db.session.add(fr)
    db.session.commit() # Flush yerine Commit (Segfault Fix)
    
    # Bildirim oluştur
    notif = Notification(user_id=to_user_id, type='friend_request', from_user_id=user_id, related_id=fr.id)
    db.session.add(notif)
    
    db.session.commit()

    from_user = User.query.get(user_id)
    socketio.emit('new_notification', {
        'type': 'friend_request',
        'from_user_username': from_user.username,
        'url': url_for('auth.friend_requests', _external=True) + f'?notif={notif.id}'
    }, room=f'user_{to_user_id}')

    if request.is_json:
        return jsonify({"message": "İstek gönderildi."}), 200
    
    flash("Arkadaşlık isteği gönderildi.", "success")
    return redirect(request.referrer or url_for('auth.add_friend_page'))

@auth_bp.route('/friend-requests', methods=['GET', 'POST'])
def friend_requests():
    user_id = session.get('user_id')
    if not user_id:
        # Çerez token'ını kontrol et
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
            else:
                response = make_response(redirect(url_for('auth.login_page')))
                response.delete_cookie('remember_token')
                return response
    
    if not user_id:
        return redirect(url_for('auth.login_page'))

    # Bildirim okundu olarak işaretle
    notif_id = request.args.get("notif")
    if notif_id:
        notif = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
        if notif:
            notif.is_read = True
            db.session.commit()

    if request.method == 'POST':
        req_id = request.form.get('request_id')
        action = request.form.get('action')
        fr = FriendRequest.query.filter_by(id=req_id, to_user_id=user_id, status='pending').first()
        if fr:
            if action == 'accept':
                # Arkadaşlığı ekle
                db.session.add(Friendship(user_id=user_id, friend_id=fr.from_user_id))
                db.session.add(Friendship(user_id=fr.from_user_id, friend_id=user_id))
                fr.status = 'accepted'
            elif action == 'reject':
                fr.status = 'rejected'
            db.session.commit()
        return redirect(url_for('auth.friend_requests'))

    # GET: gelen istekleri listele (JOIN ile optimize edildi)
    # N+1 sorgusunu engellemek için tek sorguda çekiyoruz
    results = db.session.query(FriendRequest, User).join(User, FriendRequest.from_user_id == User.id)\
                 .filter(FriendRequest.to_user_id == user_id, FriendRequest.status == 'pending').all()
    
    requests = []
    from_users = {}
    
    for req, u in results:
        requests.append(req)
        from_users[req.id] = u
        
    return render_template('friend_requests.html', requests=requests, from_users=from_users)

@auth_bp.route('/create-group', methods=['GET', 'POST'])
def create_group_page():
    user_id = session.get('user_id')
    if not user_id:
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
            else:
                response = make_response(redirect(url_for('auth.login_page')))
                response.delete_cookie('remember_token')
                return response
    if not user_id:
        return redirect(url_for('auth.login_page'))
    # Friends listesini profile_frame ile birlikte al
    friends = User.query.join(Friendship, Friendship.friend_id == User.id)\
        .filter(Friendship.user_id == user_id).all()
    if request.method == 'POST':
        group_name = request.form.get('name')
        member_ids = request.form.getlist('members')
        member_ids = [int(mid) for mid in member_ids if mid.isdigit()]
        group = create_group(group_name, user_id, member_ids)
        return redirect(url_for('auth.group_chat', group_id=group['id']))
    return render_template('create_group.html', friends=friends)

@auth_bp.route('/group/<int:group_id>/add', methods=['POST'])
def add_to_group(group_id):
    user_id = session.get('user_id')
    if not user_id:
        flash('Giriş yapmalısınız.', 'error')
        return redirect(url_for('auth.login_page'))
    
    friend_id = request.form.get('friend_id')
    if not friend_id:
         flash('Geçersiz arkadaş ID.', 'error')
         return redirect(url_for('auth.group_chat', group_id=group_id))

    success = add_user_to_group(group_id, int(friend_id))
    if success:
        flash('Arkadaş gruba eklendi.', 'success')
    else:
        flash('Arkadaş eklenirken bir hata oluştu veya grup bulunamadı.', 'error')
    
    return redirect(url_for('auth.group_chat', group_id=group_id))


@auth_bp.route('/group/<int:group_id>', methods=['GET', 'POST'])
def group_chat(group_id):
    user_id = session.get('user_id')
    if not user_id:
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
            else:
                response = make_response(redirect(url_for('auth.login_page')))
                response.delete_cookie('remember_token')
                return response
    if not user_id:
        return redirect(url_for('auth.login_page'))

    # Bildirim okundu olarak işaretle
    notif_id = request.args.get("notif")
    if notif_id:
        from .models import Notification
        notif = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
        if notif:
            notif.is_read = True
            db.session.commit()
    
    user = User.query.get(user_id)
    token = generate_token(user_id)
    
    groups = get_user_groups(user_id)
    group = next((g for g in groups if g['id'] == group_id), None)
    if not group:
        return "Bu gruba erişiminiz yok.", 403
    
    # Mesaj gönderme
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            # Kullanıcı mesajını kaydet
            save_group_message(group_id, user_id, content)
            
        return redirect(url_for('auth.group_chat', group_id=group_id))
    
    # Mesajları getir
    messages = get_group_messages(group_id)
    
    # Kullanıcı adlarını ve fotoğraflarını ekle
    for m in messages:
        # Normal kullanıcı mesajı
        sender = User.query.get(m['sender_id'])
        m['sender_username'] = sender.username if sender else 'Bilinmeyen'
        m['sender_profile_pic'] = sender.profile_pic if sender and sender.profile_pic else 'default.png'
        m['sender_profile_frame'] = sender.profile_frame if sender else 'none'
        
        if 'timestamp' not in m or not m['timestamp']:
            m['timestamp'] = 'şimdi'
    
    # Arkadaşlar (gruba eklemek için)
    friends = User.query.join(Friendship, Friendship.friend_id == User.id)\
        .filter(Friendship.user_id == user_id).all()
    
    # Grup üyelerinin adlarını ve fotoğraflarını hazırla
    group_members = []
    for uid in group['members']:
        member = User.query.get(uid)
        if member:
            group_members.append({'id': uid, 'username': member.username, 'profile_pic': member.profile_pic or 'default.png', 'profile_frame': member.profile_frame or 'none'})
        else:
            group_members.append({'id': uid, 'username': 'Bilinmeyen', 'profile_pic': 'default.png', 'profile_frame': 'none'})
    
    return render_template('group_chat.html', group=group, messages=messages, friends=friends, user=user, token=token, group_members=group_members)

@auth_bp.route('/user/<username>')
def view_profile(username):
    user_id = session.get('user_id')
    if not user_id:
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
    
    if not user_id:
        return redirect(url_for('auth.login_page'))

    profile_user = User.query.filter_by(username=username).first_or_404()
    
    # Arkadaş sayısını hesapla
    friend_count = Friendship.query.filter_by(user_id=profile_user.id).count()
    
    # İlişki durumunu hesapla
    is_friend = False
    is_blocked = False
    is_own_profile = (user_id == profile_user.id)
    
    if not is_own_profile:
        is_friend = Friendship.query.filter_by(user_id=user_id, friend_id=profile_user.id).first() is not None
        is_blocked = BlockedUser.query.filter_by(blocker_id=user_id, blocked_id=profile_user.id).first() is not None
    
    return render_template('view_profile.html', profile_user=profile_user, friend_count=friend_count, is_friend=is_friend, is_own_profile=is_own_profile, is_blocked=is_blocked)

# 6. Oturum yönetimi: Oturum yenileme ve sonlandırma endpointleri (örnek)
@auth_bp.route('/refresh-session')
def refresh_session():
    session['last_activity'] = time.time()
    return jsonify({"message": "Oturum yenilendi."})

@auth_bp.route('/logout-all')
def logout_all():
    session.clear()
    return redirect(url_for('auth.login_page'))

# 10. Log analizi/alarm (örnek: çok fazla 404 isteği atan IP'yi engelle)
HONEYPOT_COUNT = {}
HONEYPOT_LIMIT = 1000
HONEYPOT_WINDOW = 600  # 10 dakika

@auth_bp.app_errorhandler(404)
def fake_404_handler(e):
    ip = get_remote_addr()
    path = request.path
    now = time.time()
    
    # Honeypot logu ve geciktirme
    log_action("HONEYPOT_FAKE_PAGE", user=None, ip=ip, extra=f"tried_path={path}")
    time.sleep(random.uniform(1, 3))
    
    # Limit kontrolü
    entries = HONEYPOT_COUNT.get(ip, [])
    entries = [t for t in entries if now - t < current_app.config['HONEYPOT_WINDOW']]
    entries.append(now)
    HONEYPOT_COUNT[ip] = entries
    
    if len(entries) > 30: # 30+ deneme -> KALICI BAN
        if ip not in BLOCKED_IPS:
            BLOCKED_IPS.add(ip)
            save_banned_ip(ip)
        log_action("HONEYPOT_PERMANENT_BAN", user=None, ip=ip, extra=f"Sürekli tarama tespiti: {path}")
    elif len(entries) > 5: # 5+ deneme -> GEÇİCİ BAN (30 Dakika)
        TEMP_BLOCKED_IPS[ip] = time.time() + 1800
        log_action("HONEYPOT_TEMP_BAN", user=None, ip=ip, extra=f"Hız sınırlama: {path}")
        
    # Sahte bir sayfa döndür ve "banned" çerezi ekle
    response = make_response(random_fake_page())
    # Çerez her durumda eklenir, tarayıcıyı işaretlemek için
    response.set_cookie('kcord_status', 'banned', max_age=31536000, httponly=True, samesite='Strict')
    return response, 200

def random_fake_page():
    # Rastgele sahte başlık ve içerik üret
    title = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    content = ''.join(random.choices(string.ascii_letters + string.digits + " ", k=100))
    return f"<html><head><title>{title}</title></head><body><h1>{title}</h1><p>{content}</p></body></html>"

@auth_bp.before_app_request
def refresh_session():
    session['last_activity'] = time.time()

@auth_bp.route('/announcements')
def announcements():
    user_id = session.get('user_id')
    if not user_id:
        # Çerez token'ını kontrol et
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
            else:
                response = make_response(redirect(url_for('auth.login_page')))
                response.delete_cookie('remember_token')
                return response
    
    if not user_id:
        return redirect(url_for('auth.login_page'))
    
    user = User.query.get(user_id)
    
    # Tüm duyuruları getir (en yeniden eski sırasıyla)
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()
    
    # Bildirim okundu olarak işaretle
    notif_id = request.args.get("notif")
    if notif_id:
        notif = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
        if notif:
            notif.is_read = True
            db.session.commit()
    
    return render_template('announcements.html', user=user, announcements=announcements)

@auth_bp.route('/announcements/create', methods=['GET', 'POST'])
def create_announcement():
    user_id = session.get('user_id')
    if not user_id:
        # Çerez token'ını kontrol et
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
            else:
                response = make_response(redirect(url_for('auth.login_page')))
                response.delete_cookie('remember_token')
                return response
    
    if not user_id:
        return redirect(url_for('auth.login_page'))
    
    user = User.query.get(user_id)
    
    # Sadece "legend06" kullanıcısı duyuru oluşturabilir
    if user.username != "legend06":
        flash("Bu sayfaya erişim yetkiniz yok.", "error")
        return redirect(url_for('auth.announcements'))
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        is_important = request.form.get('is_important') == 'on'
        
        if not title or not content:
            flash("Başlık ve içerik alanları zorunludur.", "error")
            return render_template('create_announcement.html', user=user)
        
        if len(title) > 200:
            flash("Başlık 200 karakterden uzun olamaz.", "error")
            return render_template('create_announcement.html', user=user)
        
        # Yeni duyuru oluştur
        announcement = Announcement(
            title=title,
            content=content,
            author_id=user_id,
            is_important=is_important
        )
        db.session.add(announcement)
        db.session.commit()
        
        # Tüm kullanıcılara bildirim gönder
        all_users = User.query.filter(User.id != user_id).all()
        for target_user in all_users:
            # Bildirim oluştur
            notif = Notification(
                user_id=target_user.id, 
                type='announcement', 
                from_user_id=user_id, 
                related_id=announcement.id
            )
            db.session.add(notif)
            
            # Socket bildirimi gönder
            socketio.emit('new_notification', {
                'type': 'announcement',
                'from_user_username': user.username,
                'title': title,
                'is_important': is_important,
                'url': url_for('auth.announcements', _external=True) + f'?notif={notif.id}'
            }, room=f'user_{target_user.id}')
        
        db.session.commit()
        log_action("ANNOUNCEMENT_CREATED", user=user_id, ip=get_remote_addr(), target=title)
        
        flash("Duyuru başarıyla oluşturuldu ve tüm kullanıcılara bildirim gönderildi.", "success")
        return redirect(url_for('auth.announcements'))
    
    return render_template('create_announcement.html', user=user)

@auth_bp.route('/announcements/<int:announcement_id>/delete', methods=['POST'])
def delete_announcement(announcement_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login_page'))
    
    user = User.query.get(user_id)
    
    # Sadece "legend06" kullanıcısı duyuru silebilir
    if user.username != "legend06":
        return jsonify({"error": "Yetkiniz yok."}), 403
    
    announcement = Announcement.query.get_or_404(announcement_id)
    db.session.delete(announcement)
    flash("Duyuru başarıyla silindi.", "success")
    return redirect(url_for('auth.announcements'))

# --- E2EE API Endpoints for Groups/Communities ---

from flask import jsonify
from flask_login import login_required
import json
import os
from .models import User, Community # Assuming Community model exists

@auth_bp.route("/api/group/<int:group_id>/keys")
def get_group_public_keys(group_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Grubu DB'den çek
    group = Group.query.get(group_id)
    if not group:
         return jsonify({"error": "Group not found"}), 404
         
    # Üyeliği kontrol et
    is_member = False
    for member in group.members:
        if member.id == user_id:
            is_member = True
            break
            
    if not is_member:
        return jsonify({"error": "Bu gruba erişim izniniz yok."}), 403

    # Anahtarları topla
    keys = {}
    for member in group.members:
        if member.public_key:
            keys[str(member.id)] = member.public_key
            
    return jsonify(keys)

# --- Notification API Endpoints ---
from .security import require_api_auth

@auth_bp.route("/api/notifications", methods=["GET"])
@require_api_auth
def get_notifications_api():
    """Okunmamış bildirimleri JSON olarak döndürür"""
    user_id = g.current_user_id
    
    # Okunmamış bildirimleri çek
    notifications = Notification.query.filter_by(user_id=user_id, is_read=False)\
        .order_by(Notification.timestamp.desc()).all()
    
    result = []
    for n in notifications:
        item = {
            "id": n.id,
            "type": n.type,
            "timestamp": n.timestamp.isoformat(),
            "related_id": n.related_id,
            "is_read": n.is_read
        }
        
        # Gönderen bilgisini ekle
        if n.from_user_id:
            sender = User.query.get(n.from_user_id)
            if sender:
                item["from_user"] = sender.username
                item["from_user_pic"] = url_for('auth.serve_profile_picture', username=sender.username, _external=True)
            else:
                item["from_user"] = "System"
        
        # Mesaj içeriği veya başlık oluştur
        if n.type == 'friend_request':
            item["title"] = "Arkadaşlık İsteği"
            item["message"] = f"{item.get('from_user', 'Biri')} sana arkadaşlık isteği gönderdi."
        elif n.type == 'message':
            item["title"] = "Yeni Mesaj"
            item["message"] = f"{item.get('from_user', 'Biri')} sana mesaj gönderdi."
        elif n.type == 'group_message':
            item["title"] = "Grup Mesajı"
            group = Group.query.get(n.related_id)
            group_name = group.name if group else "Grup"
            item["message"] = f"{group_name} grubunda yeni mesaj."
        elif n.type == 'announcement':
             item["title"] = "Duyuru"
             # Duyuru başlığını çekmek için ek sorgu gerekebilir ama şimdilik basit tutalım
             item["message"] = "Yeni bir duyuru var."
        else:
             item["title"] = "Bildirim"
             item["message"] = "Yeni bir bildiriminiz var."
             
        result.append(item)
        
    return jsonify(result)

@auth_bp.route("/api/notifications/mark-read", methods=["POST"])
@require_api_auth
def mark_notification_read_api():
    """Belirli bir bildirimi okundu olarak işaretler"""
    data = request.get_json(silent=True)
    if not data or 'notification_id' not in data:
         return jsonify({"error": "notification_id gerekli"}), 400
         
    notif_id = data['notification_id']
    user_id = g.current_user_id
    
    notif = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
    if notif:
        notif.is_read = True
        db.session.commit()
        return jsonify({"success": True})
    
    return jsonify({"error": "Bildirim bulunamadı"}), 404

@auth_bp.route("/api/notifications/mark-all-read", methods=["POST"])
@require_api_auth
def mark_all_notifications_read_api():
    """Tüm bildirimleri okundu olarak işaretler"""
    user_id = g.current_user_id
    
    Notification.query.filter_by(user_id=user_id, is_read=False).update({'is_read': True})
    db.session.commit()
    
    return jsonify({"success": True})

    
    if not is_member:
         # Owner kontrolü (Eğer member listesinde yoksa bile erişebilmeli)
         if group.owner_id != int(user_id):
             return jsonify({"error": "Access denied"}), 403

    keys = {}
    for member in group.members:
        if member.public_key:
            keys[member.id] = member.public_key
            
    return jsonify(keys)

@auth_bp.route("/api/community/<int:community_id>/keys")
def get_community_public_keys(community_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    """Topluluk üyelerinin public key'lerini döndürür"""
    community = Community.query.get_or_404(community_id)
    
    # Üyeleri al (PickleType listesi)
    member_ids = community.members if community.members else []
    
    # Owner'ı da ekle (genelde üyeler listesindedir ama garanti olsun)
    if community.owner_id not in member_ids:
        member_ids.append(community.owner_id)
        
    users = User.query.filter(User.id.in_(member_ids)).all()
    
    keys = {}
    for user in users:
        if user.public_key:
            keys[user.id] = user.public_key
            
    return jsonify(keys)


@auth_bp.route('/mark-all-notifications-read', methods=['POST'])
def mark_all_notifications_read():
    user_id = session.get('user_id')
    if not user_id:
        # Cookie kontrolü
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user_id = verify_remember_token(remember_token)
            if user_id:
                session['user_id'] = user_id
            else:
                return jsonify({"error": "Giriş yapmalısınız."}), 401
        else:
            return jsonify({"error": "Giriş yapmalısınız."}), 401
    
    try:
        # Kullanıcının tüm okunmamış bildirimlerini okunmuş olarak işaretle
        updated_count = Notification.query.filter_by(
            user_id=user_id, 
            is_read=False
        ).update({'is_read': True})
        
        db.session.commit()
        
        # Log kaydet
        log_action("MARK_ALL_NOTIFICATIONS_READ", user=user_id, ip=get_remote_addr(), extra=f"Marked {updated_count} notifications as read")
        
        return jsonify({
            "message": "Tüm bildirimler okundu olarak işaretlendi.",
            "count": updated_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Bildirim işaretleme hatası: {e}")
        return jsonify({"error": "Bir hata oluştu."}), 500

@auth_bp.route('/group/<int:group_id>/settings', methods=['GET', 'POST'])
def group_settings(group_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login_page'))
    
    user = User.query.get(user_id)
    group = Group.query.get(group_id)
    
    if not group:
        flash('Grup bulunamadı.', 'danger')
        return redirect(url_for('auth.dashboard'))
    
    # Kullanıcının grup üyesi olup olmadığını kontrol et
    if user not in group.members:
        flash('Bu gruba erişim yetkiniz yok.', 'danger')
        return redirect(url_for('auth.dashboard'))

    # Sadece grup sahibi mi kontrol et
    is_owner = (group.owner_id == user_id)
    
    if request.method == 'POST':
        # Sadece grup sahibi ayarları değiştirebilir
        if not is_owner:
            flash('Sadece grup sahibi ayarları değiştirebilir.', 'danger')
            return redirect(url_for('auth.group_settings', group_id=group_id))
            
        # Grup adını güncelle
        name = request.form.get('name')
        if name and name.strip():
            group.name = name.strip()
            flash('Grup adı güncellendi.', 'success')

        photo_file = request.files.get('photo_file')
        photo_url = request.form.get('photo_url', '').strip()
        
        # Fotoğraf Dosyası Yükleme
        if photo_file and photo_file.filename:
            if allowed_file(photo_file.filename, photo_file):
                try:
                    filename = secure_filename(f"group_{group_id}_{photo_file.filename}")
                    upload_folder = os.path.join(current_app.root_path, 'static', 'group_photos')
                    os.makedirs(upload_folder, exist_ok=True)
                    filepath = os.path.join(upload_folder, filename)
                    photo_file.save(filepath)
                    
                    group.photo = f'group_photos/{filename}'
                    flash('Grup fotoğrafı yüklendi.', 'success')
                except Exception as e:
                    print(f"Photo upload error: {e}")
                    flash('Fotoğraf yüklenirken hata oluştu.', 'danger')
            else:
                 flash('Geçersiz dosya türü. Sadece resim dosyaları kabul edilir.', 'danger')

        # Fotoğraf URL Güncelleme
        elif photo_url:
            url_pattern = re.compile(
                r'^https?://'
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
                r'localhost|'
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                r'(?::\d+)?'
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            
            if url_pattern.match(photo_url):
                valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp']
                if any(photo_url.lower().endswith(ext) for ext in valid_extensions):
                    group.photo = photo_url
                    flash('Grup fotoğrafı güncellendi.', 'success')
                else:
                    flash('Geçersiz resim URLsi. Desteklenen formatlar: jpg, png, gif, webp', 'danger')
            else:
                flash('Geçersiz URL formatı.', 'danger')

        db.session.commit()
        return redirect(url_for('auth.group_settings', group_id=group_id))

    # Template için üyeleri hazırla
    members = group.members
    return render_template('group_settings.html', group=group, members=members, user=user, is_owner=is_owner)

@auth_bp.route('/group/<int:group_id>/add_member', methods=['POST'])
def add_member(group_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login_page'))
    
    from .utils import get_user_groups, add_user_to_group
    from .models import User
    
    # Kullanıcının grup sahibi olup olmadığını kontrol et
    groups = get_user_groups(user_id)
    group = next((g for g in groups if g['id'] == group_id), None)
    
    if not group or group['owner_id'] != user_id:
        flash('Bu işlemi yapmaya yetkiniz yok.', 'danger')
        return redirect(url_for('auth.group_chat', group_id=group_id))
    
    username = request.form.get('username')
    user_to_add = User.query.filter_by(username=username).first()
    
    if not user_to_add:
        flash('Kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('auth.group_settings', group_id=group_id))
    
    # Kullanıcıyı gruba ekle
    success = add_user_to_group(group_id, user_to_add.id)
    if success:
        flash(f'{username} gruba eklendi.', 'success')
    else:
        flash('Kullanıcı gruba eklenirken hata oluştu.', 'danger')
    
    return redirect(url_for('auth.group_settings', group_id=group_id))

@auth_bp.route('/group/<int:group_id>/remove_member/<int:member_id>', methods=['POST'])
def remove_member(group_id, member_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login_page'))
    
    from .utils import get_user_groups
    import json
    import os
    
    # Kullanıcının grup sahibi olup olmadığını kontrol et
    groups = get_user_groups(user_id)
    group = next((g for g in groups if g['id'] == group_id), None)
    
    if not group or group['owner_id'] != user_id:
        flash('Bu işlemi yapmaya yetkiniz yok.', 'danger')
        return redirect(url_for('auth.group_chat', group_id=group_id))
    
    # Grup sahibini çıkaramayız
    if member_id == group['owner_id']:
        flash('Grup sahibini çıkaramazsınız.', 'danger')
        return redirect(url_for('auth.group_settings', group_id=group_id))
    
    # JSON dosyasını güncelle
    GROUPS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'groups.json')
    
    if os.path.exists(GROUPS_FILE):
        with open(GROUPS_FILE, "r") as f:
            all_groups = json.load(f)
        
        # İlgili grubu bul ve üyeyi çıkar
        for g in all_groups:
            if g['id'] == group_id:
                if member_id in g['members']:
                    g['members'].remove(member_id)
                    flash('Üye gruptan çıkarıldı.', 'success')
                else:
                    flash('Üye grupta bulunamadı.', 'danger')
                break
        
        # Dosyayı kaydet
        with open(GROUPS_FILE, "w") as f:
            json.dump(all_groups, f)
    
    return redirect(url_for('auth.group_settings', group_id=group_id))


# Topluluklar (Communities) sayfası
from .models import Community

@auth_bp.route('/communities')
def communities():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login_page'))
    user = User.query.get(user_id)
    communities = Community.query.order_by(Community.created_at.desc()).all()
    return render_template('communities.html', user=user, communities=communities)

# Topluluk oluşturma sayfası (geçici)
@auth_bp.route('/create-community', methods=['GET', 'POST'])
def create_community_page():
    from .models import Community
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))

    user_id = session['user_id']
    user = User.query.get(user_id)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        avatar_file = request.files.get('avatar')

        # Validation
        if not name:
            flash('Topluluk adı gereklidir.', 'danger')
            return render_template('create_community.html', user=user)

        # Avatar upload handling
        avatar_filename = 'default.png'
        if avatar_file and avatar_file.filename:
            filename = secure_filename(avatar_file.filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ['.png', '.jpg', '.jpeg', '.gif']:
                flash('Sadece PNG, JPG, JPEG veya GIF dosyaları yükleyebilirsiniz.', 'danger')
                return render_template('create_community.html', user=user)
            avatar_dir = os.path.join(os.path.dirname(__file__), 'static', 'group_photos')
            os.makedirs(avatar_dir, exist_ok=True)
            unique_name = f"community_{int(time.time())}_{user_id}{ext}"
            avatar_path = os.path.join(avatar_dir, unique_name)
            avatar_file.save(avatar_path)
            avatar_filename = f'group_photos/{unique_name}'

        # Create and save community
        new_community = Community(
            name=name,
            description=description,
            owner_id=user_id,
            avatar=avatar_filename,
            members=[user_id],
            admins=[user_id]
        )
        db.session.add(new_community)
        db.session.commit()
        flash('Topluluk başarıyla oluşturuldu!', 'success')
        return redirect(url_for('auth.communities'))

    return render_template('create_community.html', user=user)

def datetimeformat(value):
    if isinstance(value, datetime.datetime):
        return value.strftime('%d.%m.%Y %H:%M')
    try:
        return datetime.datetime.fromtimestamp(int(value)).strftime('%d.%m.%Y %H:%M')
    except Exception:
        return str(value)
def register_filters(app):
    app.jinja_env.filters['datetimeformat'] = datetimeformat
# Topluluk detay ve mesajlaşma sayfası
@auth_bp.route('/community/<int:community_id>', methods=['GET', 'POST'])
def community_view(community_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))
    from .models import CommunityMessage, User
    user_id = session['user_id']
    user = User.query.get(user_id)
    community = Community.query.get_or_404(community_id)
    is_owner = (user_id == community.owner_id)
    
    # Is Admin check (Owner is always admin)
    # admins filed might be None if legacy, handle that
    admin_list = community.admins or []
    is_admin = is_owner or (user_id in admin_list)

    # If user is not member, show join page/button (handled in template)
    # Removing auto-join logic

    # Message sending logic
    if request.method == 'POST':
        if user_id not in community.members:
            flash("Mesaj göndermek için topluluğa katılmalısın.", "warning")
        else:
            # Permission check: Owner/Admin OR (public chat enabled)
            can_send = is_admin or (not community.only_admin_chat)
            
            if can_send:
                message = request.form.get('message', '').strip()
                # E2EE Fields
                encrypted_keys_json = request.form.get('encrypted_keys_json')
                iv = request.form.get('iv')
                
                print(f"DEBUG POST: Msg='{message}' EncroutedKeys={bool(encrypted_keys_json)}")
                
                if message:
                    print(f"DEBUG: Saving msg. Content Len: {len(message)}, Keys: {bool(encrypted_keys_json)}")
                    new_msg = CommunityMessage(
                        community_id=community.id,
                        user_id=user_id,
                        content=message,
                        encrypted_keys_json=encrypted_keys_json,
                        iv=iv
                    )
                    db.session.add(new_msg)
                    db.session.commit()
                    print("DEBUG: Commit success")
                    return redirect(url_for('auth.community_view', community_id=community.id))
            else:
                flash("Bu toplulukta sadece yöneticiler mesaj gönderebilir.", "warning")
                
            # Fallthrough for GET or failure
            return redirect(url_for('auth.community_view', community_id=community.id))

    # Mesajları DB'den çek (en yeni en altta)
    messages = CommunityMessage.query.filter_by(community_id=community.id).order_by(CommunityMessage.timestamp.asc()).all()
    # Üyelerin bilgilerini dict olarak hazırla (id -> dict)
    def user_to_dict(u):
        return {
            'id': u.id,
            'username': u.username,
            'profile_pic': u.profile_pic
        }
    users_dict = {u.id: user_to_dict(u) for u in User.query.filter(User.id.in_(community.members)).all()}
    # Ayrıca mesaj gönderenler de eklenmeli
    for m in messages:
        if m.user_id not in users_dict:
            u = User.query.get(m.user_id)
            if u:
                users_dict[u.id] = user_to_dict(u)
    
    return render_template('community_view.html', user=user, community=community, messages=messages, is_owner=is_owner, is_admin=is_admin, users_dict=users_dict)



@auth_bp.route('/community/<int:community_id>/settings/toggle_admin/<int:t_user_id>', methods=['POST'])
def toggle_community_admin(community_id, t_user_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))
        
    community = Community.query.get_or_404(community_id)
    user_id = session['user_id']
    
    if community.owner_id != user_id:
        flash("Yönetici yetkisi vermek için kurucu olmalısınız.", "error")
        return redirect(url_for('auth.community_settings', community_id=community.id))
        
    if t_user_id == community.owner_id:
        flash("Kurucunun yetkileri değiştirilemez.", "error")
        return redirect(url_for('auth.community_settings', community_id=community.id))

    if not community.admins:
        community.admins = []
        
    current_admins = list(community.admins)
    
    if t_user_id in current_admins:
        current_admins.remove(t_user_id)
        flash("Yönetici yetkisi alındı.", "info")
    else:
        current_admins.append(t_user_id)
        flash("Yönetici yetkisi verildi.", "success")
        
    community.admins = current_admins
    db.session.commit()
    return redirect(url_for('auth.community_settings', community_id=community.id))

@auth_bp.route('/community/<int:community_id>/settings', methods=['GET', 'POST'])
def community_settings(community_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))
    
    user_id = session['user_id']
    community = Community.query.get_or_404(community_id)
    
    if community.owner_id != user_id:
        flash('Bu topluluğun ayarlarını değiştirme yetkiniz yok.', 'danger')
        return redirect(url_for('auth.community_view', community_id=community.id))
        
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        only_admin_chat = request.form.get('only_admin_chat') == 'on'
        
        if name:
            community.name = name
        if description:
            community.description = description
            
        community.only_admin_chat = only_admin_chat
        
        db.session.commit()
        flash('Topluluk ayarları güncellendi.', 'success')
        return redirect(url_for('auth.community_settings', community_id=community_id))

    # Üyeleri getir
    users = User.query.filter(User.id.in_(community.members)).all()
    return render_template('community_settings.html', user=user, community=community, users=users)

@auth_bp.route('/community/<int:community_id>/kick/<int:member_id>', methods=['POST'])
def kick_community_member(community_id, member_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))
        
    user_id = session['user_id']
    community = Community.query.get_or_404(community_id)
    
    if community.owner_id != user_id:
        return "Yetkisiz işlem", 403
        
    if member_id == community.owner_id:
        flash("Topluluk sahibini atamazsınız.", "error")
        return redirect(url_for('auth.community_settings', community_id=community_id))
        
    if member_id in community.members:
        # pickle list olduğu için reassignment gerekebilir, emin olmak için
        members = list(community.members)
        if member_id in members:
            members.remove(member_id)
            community.members = members
            
            # Remove from admins if present
            if community.admins and member_id in community.admins:
                admins = list(community.admins)
                if member_id in admins:
                    admins.remove(member_id)
                    community.admins = admins
            
            db.session.commit()
            flash("Üye çıkarıldı.", "success")
            
    return redirect(url_for('auth.community_settings', community_id=community_id))

# Ana sayfadan topluluk kaldırma rotası
@auth_bp.route('/remove-community/<int:community_id>', methods=['POST'])
def remove_community_from_home(community_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Oturum açmanız gerekiyor'})
        return redirect(url_for('auth.login_page'))
        
    user_id = session['user_id']
    community = Community.query.get_or_404(community_id)
    
    # Kullanıcı üye mi kontrol et
    if user_id not in community.members:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Bu topluluğun üyesi değilsiniz'})
        flash('Bu topluluğun üyesi değilsiniz.', 'info')
        return redirect(url_for('auth.dashboard'))
    
    # Topluluk sahibi kontrolü - sahibi listeden çıkaramayız
    if user_id == community.owner_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Topluluk sahibi listeden çıkarılamaz'})
        flash('Kendinize ait bir topluluğu listeden çıkaramazsınız.', 'warning')
        return redirect(url_for('auth.dashboard'))
    
    # Topluluktan üyeliğini kaldır
    community.members.remove(user_id)
    
    # Değişiklikleri veritabanına kaydet
    db.session.commit()
    
    log_action("REMOVE_COMMUNITY", user=user_id, ip=get_remote_addr(), target=community.name)
    
    # AJAX isteği kontrolü
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json'
    if is_ajax:
        return jsonify({
            'success': True, 
            'message': 'Topluluk ana sayfadan kaldırıldı'
        })
    
    flash('Topluluk ana sayfadan kaldırıldı.', 'success')
    return redirect(url_for('auth.dashboard'))

# Topluluğa katılma rotası
@auth_bp.route('/community/<int:community_id>/join', methods=['GET', 'POST'])
def join_community(community_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Oturum açmanız gerekiyor'})
        return redirect(url_for('auth.login_page'))
        
    user_id = session['user_id']
    community = Community.query.get_or_404(community_id)
    
    # Kullanıcı zaten üye mi kontrol et
    if user_id in community.members:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Zaten bu topluluğun üyesisiniz'})
        flash('Zaten bu topluluğun üyesisiniz.', 'info')
        return redirect(url_for('auth.community_view', community_id=community.id))
    
    # Topluluğa katıl
    members = list(community.members) # Force list copy
    if user_id not in members:
        members.append(user_id)
        community.members = members
        db.session.commit()
    
    log_action("JOIN_COMMUNITY", user=user_id, ip=get_remote_addr(), target=community.name)
    
    # AJAX isteği kontrolü
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json'
    if is_ajax:
        # Kullanıcı bilgilerini hazırla
        member_info = {
            'id': user_id,
            'username': User.query.get(user_id).username,
            'profile_pic': User.query.get(user_id).profile_pic
        }
        return jsonify({
            'success': True, 
            'member_count': len(community.members),
            'member_info': member_info,
            'message': 'Topluluğa başarıyla katıldınız!'
        })
    
    flash('Topluluğa başarıyla katıldınız!', 'success')
    return redirect(url_for('auth.community_view', community_id=community.id))

# Topluluktan ayrılma rotası
@auth_bp.route('/community/<int:community_id>/leave', methods=['GET', 'POST'])
def leave_community(community_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Oturum açmanız gerekiyor'})
        return redirect(url_for('auth.login_page'))
        
    user_id = session['user_id']
    community = Community.query.get_or_404(community_id)
    
    # Topluluk sahibi ayrılamaz
    if user_id == community.owner_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Topluluk sahibi topluluktan ayrılamaz'})
        flash('Topluluk sahibi topluluktan ayrılamaz.', 'warning')
        return redirect(url_for('auth.community_view', community_id=community.id))
    
    # Kullanıcı üye mi kontrol et
    if user_id not in community.members:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Bu topluluğun üyesi değilsiniz'})
        flash('Bu topluluğun üyesi değilsiniz.', 'info')
        return redirect(url_for('auth.communities'))
    
    # Topluluktan ayrıl
    community.members.remove(user_id)
    
    # Yönetici ise listeden çıkar
    if community.admins and user_id in community.admins:
        admins = list(community.admins)
        if user_id in admins:
            admins.remove(user_id)
            community.admins = admins
    
    # Değişiklikleri veritabanına kaydet
    db.session.commit()
    
    log_action("LEAVE_COMMUNITY", user=user_id, ip=get_remote_addr(), target=community.name)
    
    # AJAX isteği kontrolü
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json'
    if is_ajax:
        # Kullanıcı bilgilerini hazırla
        member_info = {
            'id': user_id,
            'username': User.query.get(user_id).username,
            'profile_pic': User.query.get(user_id).profile_pic
        }
        return jsonify({
            'success': True, 
            'member_count': len(community.members),
            'member_info': member_info,
            'message': 'Topluluktan başarıyla ayrıldınız!'
        })
    
    flash('Topluluktan başarıyla ayrıldınız.', 'success')
    return redirect(url_for('auth.communities'))

# ================================
# MAIN BLUEPRINT ROUTES
# Footer sayfaları için route'lar
# ================================

@auth_bp.route('/privacy-policy')
def privacy_policy():
    """Gizlilik Politikası sayfası"""
    return render_template('privacy_policy.html')

@auth_bp.route('/terms-of-service')
def terms_of_service():
    """Hizmet Şartları sayfası"""
    return render_template('terms_of_service.html')

@auth_bp.route('/gdpr')
def gdpr():
    """GDPR sayfası"""
    return render_template('gdpr.html')

@auth_bp.route('/kvkk')
def kvkk():
    """KVKK1 sayfası"""
    return render_template('gdpr.html')

@auth_bp.route('/open-source-licenses')
def open_source_licenses():
    """Açık Kaynak Lisansları sayfası"""
    return render_template('open_source_licenses.html')

@auth_bp.route('/help-center')
def help_center():
    """Yardım Merkezi sayfası"""
    from .help_data import HELP_CATEGORIES
    return render_template('help_center.html', categories=HELP_CATEGORIES)

@auth_bp.route('/help-center/article/<slug>')
def help_article(slug):
    """Yardım makalesi görüntüleme"""
    from .help_data import HELP_ARTICLES
    article = HELP_ARTICLES.get(slug)
    if not article:
        abort(404)
    return render_template('help_article.html', article=article)

@auth_bp.route('/api/help/search')
def help_search():
    """Yardım arama API'si"""
    from .help_data import HELP_ARTICLES
    query = request.args.get('q', '').lower()
    
    if not query:
        return jsonify([])
        
    results = []
    for slug, article in HELP_ARTICLES.items():
        if query in article['title'].lower() or query in article['content'].lower():
            results.append({
                'title': article['title'],
                'slug': slug,
                'content': re.sub('<[^<]+?>', '', article['content'])[:100]  # Strip HTML
            })
            
    return jsonify(results)

@auth_bp.route('/forgot-password')
def forgot_password():
    """Şifremi Unuttum (Hatırlatma/Açıklama) sayfası"""
    return render_template('forgot_password.html')

@auth_bp.route('/profile-picture/<username>')
@require_auth
def serve_profile_picture(username):
    """
    Profil fotoğrafını sadece sahibine ve arkadaşlarına servis eder.
    Metadata-stripping istemci tarafında yapılmıştır.
    """
    user_id = session.get('user_id')
    target_user = User.query.filter_by(username=username).first_or_404()
    
    # Yetki Kontrolü: Sahibi mi veya Arkadaşı mı?
    is_owner = (user_id == target_user.id)
    is_friend = False
    if not is_owner:
        is_friend = Friendship.query.filter(
            ((Friendship.user_id == user_id) & (Friendship.friend_id == target_user.id)) |
            ((Friendship.user_id == target_user.id) & (Friendship.friend_id == user_id))
        ).first() is not None
    
    if is_owner or is_friend:
        if target_user.profile_pic and target_user.profile_pic != 'default.png' and not target_user.profile_pic.startswith('http'):
            # Özel fotoğraflar için cache'i kapatıyoruz ki arkadaşlık bitince erişim hemen kesilsin
            return send_from_directory(
                os.path.join(current_app.instance_path, 'profile_pics'), 
                target_user.profile_pic,
                max_age=0
            )
    
    # Default avatar public olduğu için cache'lenmesinde sakınca yok
    return send_from_directory(current_app.static_folder, 'default.png')

@auth_bp.route('/faq')
def faq():
    """Sıkça Sorulan Sorular sayfası"""
    return render_template('faq.html')

@auth_bp.route('/contact')
def contact():
    """İletişim sayfası"""
    return render_template('contact.html')

@auth_bp.route('/explicit-consent')
def explicit_consent():
    """Açık Rıza Beyanı sayfası"""
    return render_template('explicit_consent.html')
    
# --- SEO ROUTES ---
@main_bp.route('/robots.txt')
def serve_robots():
    return send_from_directory(os.path.join(current_app.root_path, '..'), 'robots.txt')

@main_bp.route('/sitemap.xml')
def serve_sitemap():
    return send_from_directory(os.path.join(current_app.root_path, '..'), 'sitemap.xml')


# ================================
# GÜVENLİK VE HESAP YÖNETİMİ
# ================================

@auth_bp.route('/block-user/<int:user_id>', methods=['POST'])
def block_user(user_id):
    current_user_id = session.get('user_id')
    if not current_user_id:
        return jsonify({"error": "Giriş yapmalısınız."}), 401
    
    if current_user_id == user_id:
        return jsonify({"error": "Kendinizi engelleyemezsiniz."}), 400
    
    existing = BlockedUser.query.filter_by(blocker_id=current_user_id, blocked_id=user_id).first()
    if existing:
        flash("Bu kullanıcı zaten engelli.", "warning")
        return redirect(request.referrer or url_for('auth.dashboard'))
    
    # Engelleme işlemi
    blocked = BlockedUser(blocker_id=current_user_id, blocked_id=user_id)
    db.session.add(blocked)
    
    # Arkadaşlığı bitir (her iki yönde de)
    Friendship.query.filter(
        ((Friendship.user_id == current_user_id) & (Friendship.friend_id == user_id)) |
        ((Friendship.user_id == user_id) & (Friendship.friend_id == current_user_id))
    ).delete()
    
    # Bekleyen istekleri temizle
    FriendRequest.query.filter(
        ((FriendRequest.from_user_id == current_user_id) & (FriendRequest.to_user_id == user_id)) |
        ((FriendRequest.from_user_id == user_id) & (FriendRequest.to_user_id == current_user_id))
    ).delete()
    
    db.session.commit()
    log_action("BLOCK_USER", user=current_user_id, target=user_id)
    flash("Kullanıcı engellendi ve arkadaşlıktan çıkarıldı.", "success")
    return redirect(url_for('auth.dashboard'))

@auth_bp.route('/unblock-user/<int:user_id>', methods=['POST'])
def unblock_user(user_id):
    current_user_id = session.get('user_id')
    if not current_user_id:
        return jsonify({"error": "Giriş yapmalısınız."}), 401
    
    BlockedUser.query.filter_by(blocker_id=current_user_id, blocked_id=user_id).delete()
    db.session.commit()
    log_action("UNBLOCK_USER", user=current_user_id, target=user_id)
    flash("Engelleme kaldırıldı.", "success")
    return redirect(request.referrer or url_for('auth.dashboard'))

@auth_bp.route('/delete-account', methods=['POST'])
def delete_account():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login_page'))
    
    password = request.form.get('password')
    user = User.query.get(user_id)
    
    if not check_password(password, user.password):
        flash("Şifre hatalı. Hesap silinemedi.", "error")
        return redirect(url_for('auth.profile'))
    
    try:
        # 1. Kullanıcının Sahip Olduğu Yapıları Tespit Et (Topluluklar)
        owned_communities = Community.query.filter_by(owner_id=user_id).all()
        
        # 2. Mesajları ve Alt Verileri Temizle
        
        # Topluluk mesajları (Kullanıcının kendi mesajları VE sahibi olduğu topluluklardaki tüm mesajlar)
        CommunityMessage.query.filter_by(user_id=user_id).delete()
        for c in owned_communities:
            CommunityMessage.query.filter_by(community_id=c.id).delete()
        
        # 3. İlişkisel Tabloları Temizle
        Notification.query.filter_by(user_id=user_id).delete()
        Notification.query.filter_by(from_user_id=user_id).delete()
        Friendship.query.filter((Friendship.user_id == user_id) | (Friendship.friend_id == user_id)).delete()
        FriendRequest.query.filter((FriendRequest.from_user_id == user_id) | (FriendRequest.to_user_id == user_id)).delete()
        ChatMessage.query.filter((ChatMessage.sender_id == user_id) | (ChatMessage.receiver_id == user_id)).delete()
        Announcement.query.filter_by(author_id=user_id).delete()
        RememberToken.query.filter_by(user_id=user_id).delete()
        BlockedUser.query.filter((BlockedUser.blocker_id == user_id) | (BlockedUser.blocked_id == user_id)).delete()
        
        # 4. Ana Yapıları Sil (Sahiplikler)
        for c in owned_communities:
            db.session.delete(c)
        
        # Kullanıcının sahibi olduğu grupları sil
        Group.query.filter_by(owner_id=user_id).delete()
        
        # 5. Üyelik Listelerinden Temizle (PickleType)
        all_groups = Group.query.all()
        for g in all_groups:
            if user_id in g.members:
                g.members.remove(user_id)
                db.session.add(g)
        
        all_communities = Community.query.all()
        for c in all_communities:
            if user_id in c.members:
                c.members.remove(user_id)
            if user_id in c.admins:
                c.admins.remove(user_id)
            db.session.add(c)
        
        # 6. Kullanıcı Kaydını Sil
        db.session.delete(user)
        db.session.commit()
        
        log_action("DELETE_ACCOUNT", user=user_id)
        session.clear()
        flash("Hesabınız kalıcı olarak silindi. Hoşçakalın.", "info")
        return redirect(url_for('auth.welcome'))
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting account: {e}")
        flash("Hesap silinirken bir hata oluştu.", "error")
        return redirect(url_for('auth.profile'))

# --- KEYCORD SMART 404 HANDLER ---
@auth_bp.app_errorhandler(404)
def smart_404_handler(e):
    path = request.path
    # Botlar genellikle bu uzantıları tarar
    suspicious_patterns = ['.php', '.asp', '.aspx', '.env', '/wp-', '/admin', '/config', '/backup', '.sql', '.git']
    if any(pattern in path.lower() for pattern in suspicious_patterns):
        try:
            return random_fake_page(), 200, {'Content-Type': 'text/html'}
        except:
            return "Bot Detected", 200
    
    # Gerçek kullanıcılar için şık 404 sayfası
    return render_template('404.html'), 404
