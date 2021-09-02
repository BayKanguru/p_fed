"""
Encryption and decryption of data
"""

import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(data, password, salt, initialization_vector):
    """Encrypts the data using AES-CBC and PBKDF2HMAC as 
    key derivation function from the password 
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


def decrypt(data, password, salt, initialization_vector):
    """Decrypts the data generated from "encrypt" function 
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
