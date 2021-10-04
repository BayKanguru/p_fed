"""functions for encryption/decryption of data with passwords.  Works
only if every argument is same except data.
"""

import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(
        data: bytes,
        password: str,
        salt: bytes,
        initialization_vector: bytes = None,
        pbkdf2_hash_algorithm=hashes.SHA3_512,
        pbkdf2_lenght=32,
        pbkdf2_iterations=1000000,
        password_encoding="utf8",
        encryption_algorithm=algorithms.AES,
        encryption_nonce=None,
        mode=modes.CBC,
        mode_tweak=None,
        mode_nonce=None) -> bytes:
    """Encrypts the data using AES256-CBC.  Key derivation from
    password is done using PBKDF2HMAC.  Padding for AES256 is done
    using PKCS7.
    """

    kdf = PBKDF2HMAC(
        algorithm=pbkdf2_hash_algorithm(),
        length=pbkdf2_lenght,
        salt=salt,
        iterations=pbkdf2_iterations
    )
    key = kdf.derive(bytes(password, encoding=password_encoding))

    block_size = encryption_algorithm.block_size
    padder = padding.PKCS7(block_size).padder()
    padded = padder.update(data) + padder.finalize()

    if encryption_algorithm.name == "ChaCha20":
        cipher = Cipher(encryption_algorithm(key, encryption_nonce),
                        modes. CBC(initialization_vector))
    else:
        if mode.name == "XTS":
            cipher = Cipher(encryption_algorithm(key),
                            mode(mode_nonce))
        elif mode.name == "CTR":
            cipher = Cipher(encryption_algorithm(key),
                            mode(mode_tweak))
        elif mode.name == "GCM":
            cipher = Cipher(encryption_algorithm(key),
                            mode(initialization_vector))
        else:
            cipher = Cipher(encryption_algorithm(key),
                            mode(initialization_vector))

    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    return encrypted


def decrypt(
        data: bytes,
        password: str,
        salt: bytes,
        initialization_vector: bytes = None,
        pbkdf2_hash_algorithm=hashes.SHA3_512,
        pbkdf2_lenght=32,
        pbkdf2_iterations=1000000,
        password_encoding="utf8",
        encryption_algorithm=algorithms.AES,
        encryption_nonce=None,
        mode=modes.CBC,
        mode_tweak=None,
        mode_nonce=None) -> bytes:
    """Decrypts AES256-CBC encrypted data using a password.  Only
    decrypts correctly if key derivation algorithm, padding algorithm,
    salt and initialization_vector are the same as encryption.
    """
    kdf = PBKDF2HMAC(
        algorithm=pbkdf2_hash_algorithm(),
        length=pbkdf2_lenght,
        salt=salt,
        iterations=pbkdf2_iterations
    )
    key = kdf.derive(bytes(password, encoding=password_encoding))

    if encryption_algorithm.name == "ChaCha20":
        cipher = Cipher(encryption_algorithm(key, encryption_nonce),
                        modes. CBC(initialization_vector))
    else:
        if mode.name == "XTS":
            cipher = Cipher(encryption_algorithm(key),
                            mode(mode_nonce))
        elif mode.name == "CTR":
            cipher = Cipher(encryption_algorithm(key),
                            mode(mode_tweak))
        elif mode.name == "GCM":
            cipher = Cipher(encryption_algorithm(key),
                            mode(initialization_vector))
        else:
            cipher = Cipher(encryption_algorithm(key),
                            mode(initialization_vector))

    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()

    block_size = encryption_algorithm.block_size
    padder = padding.PKCS7(block_size).unpadder()
    unpadded = padder.update(decrypted) + padder.finalize()

    return unpadded
