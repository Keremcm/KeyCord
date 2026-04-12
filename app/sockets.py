from flask_socketio import emit, join_room, leave_room
from flask import request, url_for, session
from app import socketio, db
from .models import ChatMessage, Friendship, User, Notification, BlockedUser, Group
from .utils import verify_token, get_group_messages
from datetime import datetime
from .utils import save_group_message, get_user_groups, save_group_notification, get_group_members, get_group_name
from .security import (
    socket_auth_required, verify_secure_token, log_security_event,
    rate_limit_check, sanitize_message_content, validate_friendship,
    validate_group_access, get_remote_addr
)
import time
import logging
import os
import json
import random

# Log dosyası ayarları (routes.py ile aynı klasöre yazılır)
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

# --- SOCKET RATE LIMITING ---
SOCKET_RATE_LIMITS = {}  # {ip: [timestamps]}
SOCKET_RATE_LIMIT_WINDOW = 60  # saniye
SOCKET_RATE_LIMIT_MAX = 1000    # 1 dakikada 1000 event (User Request: loosened)

def is_socket_rate_limited(ip, max_req=SOCKET_RATE_LIMIT_MAX, window=SOCKET_RATE_LIMIT_WINDOW):
    now = time.time()
    timestamps = SOCKET_RATE_LIMITS.get(ip, [])
    timestamps = [t for t in timestamps if now - t < window]
    if len(timestamps) >= max_req:
        log_action("SOCKET_DOS_BLOCK", user=None, ip=ip, extra=f"socket_limit={max_req}/{window}s")
        return True
    timestamps.append(now)
    SOCKET_RATE_LIMITS[ip] = timestamps
    return False


@socketio.on("join")
@socket_auth_required
def handle_join(data):
    token = data.get("token")
    user_id = verify_token(token)  # verify_secure_token yerine verify_token
    if not user_id:
        return emit("error", {"message": "Token geçersiz."})

    room = f"user_{user_id}"
    join_room(room)
    emit("joined", {"room": room})
    log_security_event('SOCKET_JOIN', f'User: {user_id}, Room: {room}')
    print(f"Kullanıcı {user_id} odaya katıldı: {room}")

@socketio.on("send_message")
@socket_auth_required
def handle_send_message(data):
    token = data.get("token")
    content = data.get("content", "").strip()
    receiver_username = data.get("to", "").strip()

    sender_id = verify_secure_token(token)
    if not sender_id:
        return emit("error", {"message": "Token geçersiz."})

    # Input validasyonu
    if not content or not receiver_username:
        return emit("error", {"message": "Mesaj içeriği ve alıcı gerekli."})

    # Mesaj içeriği sanitizasyonu
    sanitized_content = sanitize_message_content(content)
    if not sanitized_content:
        return emit("error", {"message": "Mesaj içeriği geçersiz."})

    # Rate limiting kontrolü
    ip = get_remote_addr()
    if is_socket_rate_limited(ip):
        emit("error", {"message": "Çok fazla istek. Lütfen bekleyin."})
        return

    receiver = User.query.filter_by(username=receiver_username).first()
    if not receiver:
        return emit("error", {"message": "Alıcı bulunamadı."})

    # Arkadaşlık kontrolü
    if not validate_friendship(sender_id, receiver.id):
        return emit("error", {"message": "Arkadaş değilsiniz."})

    # Engelleme kontrolü
    is_blocked = BlockedUser.query.filter(
        ((BlockedUser.blocker_id == sender_id) & (BlockedUser.blocked_id == receiver.id)) |
        ((BlockedUser.blocker_id == receiver.id) & (BlockedUser.blocked_id == sender_id))
    ).first()
    
    if is_blocked:
        return emit("error", {"message": "Bu kullanıcıyla iletişim kuramazsınız."})


    
    
    # E2EE Fields
    encrypted_aes_key = data.get("encrypted_aes_key")
    encrypted_aes_key_sender = data.get("encrypted_aes_key_sender")
    iv = data.get("iv")

    message = ChatMessage(
        sender_id=sender_id,
        receiver_id=receiver.id,
        content=sanitized_content,
        encrypted_aes_key=encrypted_aes_key,
        encrypted_aes_key_sender=encrypted_aes_key_sender,
        iv=iv
    )
    db.session.add(message)
    
    # Bildirim oluştur
    notif = Notification(user_id=receiver.id, type='message', from_user_id=sender_id, related_id=sender_id)
    db.session.add(notif)

    db.session.commit()

    sender = User.query.get(sender_id)

    # Güvenlik logu
    log_security_event('SOCKET_MESSAGE_SENT', f'From: {sender.username}, To: {receiver_username}')

    redirect_url = url_for('auth.messages', _external=True) + f'?with={sender_id}&notif={notif.id}'

    # Ortak Payload Verileri
    base_payload = {
        "from": sender.username,
        "to": receiver.username,
        "content": sanitized_content,
        "iv": iv,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Alıcı için Payload (Onun anahtarıyla şifrelenmiş AES key)
    payload_receiver = base_payload.copy()
    payload_receiver["encrypted_aes_key"] = encrypted_aes_key
    
    # Gönderici için Payload (Kendi anahtarıyla şifrelenmiş AES key)
    payload_sender = base_payload.copy()
    payload_sender["encrypted_aes_key"] = encrypted_aes_key_sender

    # Göndericiye hemen ilet (UX için)
    emit("receive_message", payload_sender, room=f"user_{sender_id}")

    # Alıcıya ve bildirimlere rastgele gecikme ekle (Anonimlik için)
    def delayed_forward():
        delay = random.uniform(1, 4)  # 1-4 saniye rastgele gecikme
        socketio.sleep(delay)
        
        # Alıcıya mesajı ilet
        socketio.emit("receive_message", payload_receiver, room=f"user_{receiver.id}")
        
        # Bildirim gönder
        socketio.emit('new_notification', {
            'type': 'message',
            'from_user_username': sender.username,
            'from_user_id': sender.id,
            'url': redirect_url
        }, room=f'user_{receiver.id}')

    socketio.start_background_task(delayed_forward)

@socketio.on("join_group")
@socket_auth_required
def handle_join_group(data):
    token = data.get("token")
    group_id = data.get("group_id")
    
    # Token doğrulama
    user_id = verify_token(token)
    if not user_id:
        return emit("error", {"message": "Token geçersiz."})
    
    # Group ID validation
    try:
        group_id = int(group_id)
    except (ValueError, TypeError):
        return emit("error", {"message": "Geçersiz grup ID."})
    
    # Grup erişim kontrolü (DB check)
    user = User.query.get(user_id)
    group = Group.query.get(group_id)
    
    if not group or not user or user not in group.members:
        return emit("error", {"message": "Bu gruba erişiminiz yok."})
    
    room = f"group_{group_id}"
    try:
        join_room(room, namespace='/')
        emit("joined_group", {"room": room}, namespace='/')
        log_security_event('SOCKET_JOIN_GROUP', f'Group: {group_id}', user_id=user_id)
    except Exception as e:
        print(f"DEBUG: join_room failed: {e}")
        emit("error", {"message": f"Grup odasına katılamadı: {str(e)}"}, namespace='/')

@socketio.on("send_group_message")
@socket_auth_required
def handle_send_group_message(data):
    group_id = data.get("group_id")
    content = data.get("content", "").strip() # Encrypted content blob if E2EE
    
    # E2EE Fields
    encrypted_keys_json = data.get("encrypted_keys_json")
    iv = data.get("iv")
    
    sender_id = session.get("user_id")
    
    if not group_id or not content or not sender_id:
        return emit("error", {"message": "Eksik bilgi."})
    
    # Güvenlik kontrolleri
    if len(content) > 5000:
         return emit("error", {"message": "Mesaj çok uzun."})
         
    # Grup Erişim Kontrolü (DB check + IDOR fix)
    user = User.query.get(sender_id)
    group = Group.query.get(group_id)
    if not group or not user or user not in group.members:
        return emit("error", {"message": "Bu gruba erişiminiz yok."})
    
    # Mesajı kaydet
    msg = save_group_message(
        group_id=group_id, 
        sender_id=sender_id, 
        content=content, 
        encrypted_keys_json=encrypted_keys_json, 
        iv=iv
    )
    
    if not msg:
        return emit("error", {"message": "Mesaj kaydedilemedi."})
    
    # Payload hazırla
    sender_user = User.query.get(sender_id)
    payload = {
        "group_id": int(group_id),
        "sender_id": sender_id,
        "sender_username": sender_user.username if sender_user else f"User{sender_id}",
        "sender_profile_pic": sender_user.profile_pic if sender_user else None,
        "content": content,
        "encrypted_keys_json": encrypted_keys_json,
        "iv": iv,
        "timestamp": msg.timestamp.strftime("%H:%M"),
        "message_type": "user"
    }
    
    # Göndericiye hemen ilet (hızlı geri bildirim için)
    emit("receive_group_message", payload, room=f"user_{sender_id}")
    
    # Bildirimleri ve Diğer Üyelere Mesajı Gecikmeli Gönder
    try:
        member_ids = get_group_members(group_id)
        
        def delayed_group_forward():
            delay = random.uniform(1, 4)
            socketio.sleep(delay)
            
            # Diğer üyelere mesajı ilet (Gönderici odasında değilse ona gitmez, ama biz göndericiye zaten emit ettik)
            # SocketIO odasından göndericiyi hariç tutmak için:
            # Buradaki oda group_{group_id} tüm üyeleri içerir.
            # Biz sadece "receive_group_message"ı odaya basıyoruz. 
            # Gönderici zaten "receive_group_message"ı aldığı için (emit yukarda), 
            # odaya basıldığında tekrar alabilir (client tarafında ignore edilmeli veya burada hariç tutulmalı).
            # KeyCord istemcisi genellikle msg_id veya timestamp ile duplicate kontrolü yapar.
            
            socketio.emit("receive_group_message", payload, room=f"group_{group_id}")
            
            for member_id in member_ids:
                if member_id != sender_id:
                    # Bildirimi kaydet
                    save_group_notification(group_id, sender_id, member_id, msg.id)
                    
                    # Socket ile anlık bildirim
                    socketio.emit('new_notification', {
                        'type': 'group_message',
                        'from_user_username': sender_user.username,
                        'group_name': group.name,
                        'group_id': group_id,
                        'url': url_for('auth.group_chat', group_id=group_id, _external=True)
                    }, room=f'user_{member_id}')
        
        socketio.start_background_task(delayed_group_forward)
        db.session.commit()
        
    except Exception as e:
        print(f"Grup bildirim hatası: {e}")

# Helper functions moved to utils.py

