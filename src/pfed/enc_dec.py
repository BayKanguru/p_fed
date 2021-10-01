"""functions for encryption/decryption of data with passwords.  Works 
only if every argument is same except data.
"""

import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(data: bytes, password: str, salt: bytes, initialization_vector: bytes) -> bytes:
    """Encrypts the data using AES256-CBC.  Key derivation from 
    password is done using PBKDF2HMAC.  Padding for AES256 is done
    using PKCS7.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=salt,
        iterations=1000000
    )
    key = kdf.derive(bytes(password, encoding="utf8"))

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    return encrypted


def decrypt(data: bytes, password: str, salt: bytes, initialization_vector: bytes) -> bytes:
    """Decrypts AES256-CBC encrypted data using a password.  Only 
    decrypts correctly if key derivation algorithm, padding algorithm, 
    salt and initialization_vector are the same as encryption.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=salt,
        iterations=1000000
    )
    key = kdf.derive(bytes(password, encoding="utf8"))

    cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(decrypted) + unpadder.finalize()

    return unpadded
