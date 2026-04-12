from . import db
import datetime

# Association Table for Group Members
group_members = db.Table('group_members',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

# Grup modeli
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    photo = db.Column(db.String(255), default='default.png')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    owner = db.relationship('User', backref='owned_groups')
    members = db.relationship('User', secondary=group_members, lazy='subquery',
        backref=db.backref('joined_groups', lazy=True))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # password_hash yerine password
    profile_pic = db.Column(db.String(255), default='default.png')
    profile_frame = db.Column(db.String(20), default='none')  # Profil çerçevesi
    about = db.Column(db.Text, default='')
    games = db.Column(db.String(255), default='')
    is_verified = db.Column(db.Boolean, default=False)

    # E2EE Keys
    public_key = db.Column(db.Text, nullable=True)  # Diğer kullanıcılar için RSA/X25519 Public Key
    encrypted_private_key = db.Column(db.Text, nullable=True)  # Kullanıcının şifresiyle şifrelenmiş RSA/X25519 Private Key
    salt = db.Column(db.String(64), nullable=True)  # Şifreden anahtar türetmek için tuz

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # __table_args__ can be defined here if needed, e.g.:
    __table_args__ = (db.UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),)
    
class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Artık nullable, grup mesajı için
    group_id = db.Column(db.Integer, nullable=True)  # Grup mesajı için
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # E2EE Fields
    encrypted_aes_key = db.Column(db.Text, nullable=True)  # Alıcının public key'i ile şifrelenmiş AES anahtarı
    encrypted_aes_key_sender = db.Column(db.Text, nullable=True)  # Göndericinin public key'i ile şifrelenmiş AES anahtarı
    encrypted_keys_json = db.Column(db.Text, nullable=True) # GRUP İÇİN: {user_id: encrypted_key} haritası
    iv = db.Column(db.String(64), nullable=True)  # AES-GCM IV (Base64)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(20))  # 'friend_request', 'message'
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    related_id = db.Column(db.Integer)  # friend_request_id veya mesaj id
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class RememberToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_important = db.Column(db.Boolean, default=False)  # Önemli duyurular için
    
    # Relationship
    author = db.relationship('User', backref='announcements')

class Community(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default='')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    avatar = db.Column(db.String(255), default='default.png')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    members = db.Column(db.PickleType, default=list)  # Üye id'leri listesi
    admins = db.Column(db.PickleType, default=list)   # Yönetici id'leri listesi
    only_admin_chat = db.Column(db.Boolean, default=False)  # Sadece yöneticiler mesaj atabilir

    owner = db.relationship('User', backref='owned_communities')
    
# Topluluk mesaj modeli
class CommunityMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # E2EE Fields
    encrypted_keys_json = db.Column(db.Text, nullable=True) # {user_id: encrypted_key}
    iv = db.Column(db.String(64), nullable=True)

    user = db.relationship('User', backref='community_messages')
    community = db.relationship('Community', backref='messages')

class BlockedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('blocker_id', 'blocked_id', name='unique_block'),)