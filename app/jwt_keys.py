import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'keys')
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, 'jwt_private_key.pem')
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, 'jwt_public_key.pem')

def ensure_keys_exist():
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        print(f"Generating new Ed25519 key pair for JWT signing...")
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Save private key
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"Keys saved to {KEYS_DIR}")

def load_private_key():
    ensure_keys_exist()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    ensure_keys_exist()
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())
