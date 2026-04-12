import jwt, datetime
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
import base64
import json
import os
import secrets
from .models import RememberToken, User, ChatMessage, Group
from . import db

# LEGACY ENCRYPTION REMOVED - E2EE IMPLEMENTED
# Eski anahtarlar ve fonksiyonlar güvenlik nedeniyle kaldırıldı.
# Artık şifreleme istemci tarafında (Client-Side) yapılıyor.

def generate_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=6)
    }
    secret = current_app.config["SECRET_KEY"]
    return jwt.encode(payload, secret, algorithm="HS256")

def verify_token(token):
    try:
        secret = current_app.config["SECRET_KEY"]
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def hash_password(password):
    return generate_password_hash(password)

def check_password(password, hashed):
    return check_password_hash(hashed, password)

MESSAGES_FILE = "instance/messages.json"

def save_message(sender_id, receiver_id, content, encrypted_aes_key=None, iv=None):
    msg = ChatMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        content=content, # Encrypted Blob
        encrypted_aes_key=encrypted_aes_key,
        iv=iv,
        timestamp=datetime.datetime.utcnow()
    )
    db.session.add(msg)
    db.session.commit()

def get_conversation(user1, user2):
    # LEGACY FUNCTION - Deprecated in favor of direct DB queries
    return []

def generate_remember_token(user_id):
    """Güvenli bir 'beni hatırla' token'ı oluşturur"""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    
    remember_token = RememberToken(
        user_id=user_id,
        token=token,
        expires_at=expires_at
    )
    db.session.add(remember_token)
    db.session.commit()
    
    return token

def verify_remember_token(token):
    """Çerez token'ını doğrular ve kullanıcı ID'sini döndürür"""
    if not token:
        return None
    
    remember_token = RememberToken.query.filter(
        RememberToken.token == token,
        RememberToken.expires_at > datetime.datetime.utcnow()
    ).first()
    
    if remember_token:
        return remember_token.user_id
    return None

def delete_remember_token(token):
    """Çerez token'ını veritabanından siler"""
    RememberToken.query.filter_by(token=token).delete()
    db.session.commit()

def delete_user_remember_tokens(user_id):
    """Kullanıcının tüm çerez token'larını siler"""
    RememberToken.query.filter_by(user_id=user_id).delete()
    db.session.commit()

def create_group(group_name, owner_id, member_ids):
    new_group = Group(
        name=group_name,
        owner_id=owner_id
    )
    db.session.add(new_group)
    
    # Add owner as member
    owner = User.query.get(owner_id)
    if owner:
        new_group.members.append(owner)
        
    # Add other members
    for uid in member_ids:
        user = User.query.get(uid)
        if user and user not in new_group.members:
            new_group.members.append(user)
            
    db.session.commit()
    
    return {
        "id": new_group.id,
        "name": new_group.name,
        "owner_id": new_group.owner_id,
        "members": [m.id for m in new_group.members]
    }

def add_user_to_group(group_id, user_id):
    group = Group.query.get(group_id)
    user = User.query.get(user_id)
    
    if not group or not user:
        return False
    
    if user not in group.members:
        group.members.append(user)
        db.session.commit()
    return True

def get_user_groups(user_id):
    user = User.query.get(user_id)
    if not user:
        return []
        
    user_groups = []
    for g in user.joined_groups:
        user_groups.append({
            "id": g.id,
            "name": g.name,
            "owner_id": g.owner_id,
            "members": [m.id for m in g.members],
            "photo": g.photo
        })
    return user_groups

def get_group_members(group_id):
    group = Group.query.get(group_id)
    return [m.id for m in group.members] if group else []

def get_group_name(group_id):
    group = Group.query.get(group_id)
    return group.name if group else "Bilinmeyen Grup"

def save_group_message(group_id, sender_id, content, encrypted_keys_json=None, iv=None):
    """Grup mesajını veritabanına kaydeder."""
    msg = ChatMessage(
        group_id=group_id,
        sender_id=sender_id,
        content=content,
        timestamp=datetime.datetime.now(),
        encrypted_keys_json=encrypted_keys_json,
        iv=iv
    )
    db.session.add(msg)
    try:
        db.session.commit()
        return msg
    except Exception as e:
        db.session.rollback()
        print(f"Error saving group message: {e}")
        return None

def get_group_messages(group_id):
    """Gruba ait son mesajları getirir."""
    # Sadece group_id'si dolu olan mesajları getir
    messages = ChatMessage.query.filter_by(group_id=group_id).order_by(ChatMessage.timestamp).all()
    result = []
    
    for msg in messages:
        sender = User.query.get(msg.sender_id)
        result.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'sender_username': sender.username if sender else "Unknown",
            'sender_profile_pic': sender.profile_pic if sender else "default.png",
            'content': msg.content,
            'timestamp': msg.timestamp.strftime("%H:%M"),
            'encrypted_keys_json': msg.encrypted_keys_json,
            'iv': msg.iv
        })
    return result

def save_group_notification(group_id, from_user_id, to_user_id, message_id=None):
    """
    Veritabanına bildirim kaydeder (Eski JSON dosyasını kullanmaz)
    deprecated: message_id argüman uyumluluğu için tutuldu
    """
    # Zaten Notification tablomuz var, onu kullanıyoruz.
    # Bu fonksiyon sadece eski API uyumluluğu için wrapper görevi görebilir
    # Ancak doğrusu doğrudan DB session kullanmaktır.
    # Burada sadece Notification modeli oluşturup kaydediyoruz.
    
    # Hali hazırda bu fonksiyonu çağıran yerler için:
    notif = Notification(
        user_id=to_user_id,
        type='group_message',
        from_user_id=from_user_id,
        related_id=group_id,
        is_read=False,
        timestamp=datetime.datetime.utcnow()
    )
    db.session.add(notif)
    # Commit caller sorumluluğunda olabilir ama burada yapalım
    # (Dikkat: Nested commit iyi değildir ama wrapper olduğu için OK)
    try:
        db.session.commit()
    except:
        db.session.rollback()

def get_user_group_notifications(user_id):
    return Notification.query.filter_by(
        user_id=user_id, 
        type='group_message', 
        is_read=False
    ).all()

def mark_group_notification_read(user_id, group_id):
    notifications = Notification.query.filter_by(
        user_id=user_id,
        type='group_message',
        related_id=group_id,
        is_read=False
    ).all()
    
    for n in notifications:
        n.is_read = True
    
    db.session.commit()

def get_group_name(group_id):
    """Grup ID'den grup adını döndürür (Veritabanından)"""
    group = Group.query.get(group_id)
    return group.name if group else "Bilinmeyen Grup"
