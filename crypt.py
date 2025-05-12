import os
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import InvalidToken
from cryptography.fernet import Fernet


class DecryptionError(Exception):
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt(data: bytes, password: str, original_extension: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)

    encrypted = f.encrypt(data)

    extension_bytes = original_extension.encode("utf-8")

    return salt + len(extension_bytes).to_bytes(4, "big") + extension_bytes + encrypted


def decrypt(data: bytes, password: str) -> bytes:
    salt = data[:16]

    extension_length = int.from_bytes(data[16:20], "big")
    original_extension = data[20 : 20 + extension_length].decode("utf-8")

    encrypted = data[20 + extension_length :]

    key = derive_key(password, salt)
    f = Fernet(key)

    try:
        decrypted = f.decrypt(encrypted)
        return decrypted, original_extension
    except InvalidToken:
        raise DecryptionError(
            "Decryption failed. The password or file/directory path may be incorrect."
        )
