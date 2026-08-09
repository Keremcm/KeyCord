import os
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'keys')
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, 'jwt_private_key.pem')
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, 'jwt_public_key.pem')


def _get_key_password() -> bytes:
    """Ortam değişkeninden anahtar şifresini al. Yoksa uyar ve varsayılan kullan."""
    password = os.environ.get('JWT_KEY_PASSWORD', '')
    if not password:
        logging.warning("JWT_KEY_PASSWORD_NOT_SET private key will be unencrypted")
        return b''
    return password.encode('utf-8')


def ensure_keys_exist():
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        logging.info("JWT_KEYGEN_GENERATING type=ed25519")
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        password = _get_key_password()
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        # Save private key (şifreli)
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))
        # Sadece owner okuyabilsin
        os.chmod(PRIVATE_KEY_PATH, 0o600)

        # Save public key
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        logging.info(f"JWT_KEYGEN_SAVED dir={KEYS_DIR}")


_private_key_cache = None
_public_key_cache = None


def load_private_key():
    """JWT imzalama için özel anahtarı yükler (her çağrıda PEM okumayı önlemek için cache'ler)."""
    global _private_key_cache
    if _private_key_cache is not None:
        return _private_key_cache
    ensure_keys_exist()
    password = _get_key_password()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        _private_key_cache = serialization.load_pem_private_key(
            f.read(),
            password=password if password else None
        )
    return _private_key_cache


def load_public_key():
    """JWT doğrulama için public anahtarı yükler (cache'li)."""
    global _public_key_cache
    if _public_key_cache is not None:
        return _public_key_cache
    ensure_keys_exist()
    with open(PUBLIC_KEY_PATH, "rb") as f:
        _public_key_cache = serialization.load_pem_public_key(f.read())
    return _public_key_cache
