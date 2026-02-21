# crypto.py
# Helpers for deriving a symmetric key from a master password and encrypting/decrypting data.

import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Note: Fernet uses AES in CBC mode with PKCS7 padding, HMAC for integrity.

# We store the salt alongside the encrypted data, encoded as: salt||b'::'||token (both base64)
SALT_SEPARATOR = b'::SALT::'

def derive_key(master_password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive a Fernet key from the master_password.
       If salt is None, a new random salt is generated and returned along with the key.
    Returns (key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt

def encrypt(plain_text: str, master_password: str) -> bytes:
    """Encrypt plain_text using a key derived from master_password.
       Returns bytes that contain salt + separator + token, all base64-encoded when stored as text.
    """
    key, salt = derive_key(master_password)
    f = Fernet(key)
    token = f.encrypt(plain_text.encode())
    # store salt + separator + token. Both are already bytes. We'll base64 encode the whole if needed.
    combined = base64.urlsafe_b64encode(salt) + SALT_SEPARATOR + token
    return combined

def decrypt(combined: bytes, master_password: str) -> str:
    """Decrypt combined payload using master_password."""
    if SALT_SEPARATOR not in combined:
        raise ValueError("Invalid data format: salt separator not found.")
    salt_b64, token = combined.split(SALT_SEPARATOR, 1)
    salt = base64.urlsafe_b64decode(salt_b64)
    key, _ = derive_key(master_password, salt=salt)
    f = Fernet(key)
    decrypted = f.decrypt(token)
    return decrypted.decode()
