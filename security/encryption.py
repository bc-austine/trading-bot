# security/encryption.py
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional

class EncryptionService:
    """Service for encrypting and decrypting sensitive data"""
    
    def __init__(self, password: str, salt: Optional[str] = None):
        self.password = password.encode()
        self.salt = base64.urlsafe_b64decode(salt.encode()) if salt else os.urandom(16)
        self.key = self._derive_key()
        self.fernet = Fernet(self.key)
    
    def _derive_key(self) -> bytes:
        """Derive a key from the password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password))
    
    def encrypt(self, data: str) -> str:
        """Encrypt a string"""
        encrypted_data = self.fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt a string"""
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        return self.fernet.decrypt(encrypted_bytes).decode()
    
    def get_salt(self) -> str:
        """Get the salt used for key derivation"""
        return base64.urlsafe_b64encode(self.salt).decode()