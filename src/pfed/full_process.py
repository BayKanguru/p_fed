import os
import sys
import getpass
import pathlib
import datetime
import argparse

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import pfed.enc_dec as ed
import pfed.formatting as fmt


def encrypt_and_prepare(
        password,
        repeated_password,
        input_data,
        scrypt_salt_lenght=128,
        scrypt_lenght=512,
        scrypt_n=2**20,
        scrypt_r=8,
        scrypt_p=1,
        password_encoding="utf8",
        encryption_salt_lenght=128,
        pbkdf2_hash_algorithm=hashes.SHA3_512,
        pbkdf2_lenght=32,
        pbkdf2_iterations=1000000,
        encryption_algorithm=algorithms.AES,
        encryption_nonce=None,
        mode=modes.CBC,
        iv=None,
        mode_tweak=None,
        mode_nonce=None):

    if not password == repeated_password:
        raise ValueError("Passwords do not match")
    if type(input_data) is not bytes:
        raise TypeError("input_data should be bytes")

    scrypt_salt = os.urandom(scrypt_salt_lenght)
    pass_storage_kdf = Scrypt(
        salt=scrypt_salt,
        length=scrypt_lenght,
        n=scrypt_n,
        r=scrypt_r,
        p=scrypt_p
    )

    password_digested = pass_storage_kdf.derive(
        bytes(password, encoding=password_encoding))

    encryption_salt = os.urandom(encryption_salt_lenght)

    encrypted = ed.encrypt(
        input_data,
        password,
        encryption_salt,
        iv,
        pbkdf2_hash_algorithm=pbkdf2_hash_algorithm,
        pbkdf2_lenght=pbkdf2_lenght,
        pbkdf2_iterations=pbkdf2_iterations,
        password_encoding=password_encoding,
        encryption_algorithm=encryption_algorithm,
        encryption_nonce=encryption_nonce,
        mode=mode,
        mode_tweak=mode_tweak,
        mode_nonce=mode_nonce)

    formatted_data = fmt.format_encrypted_data(
        encrypted,
        encryption_salt,
        scrypt_salt,
        password_digested,
        iv=iv,
        encryption_nonce=encryption_nonce,
        mode_tweak=mode_tweak,
        mode_nonce=mode_nonce)

    return formatted_data


def decrypt_and_prepare(
        password,
        input_data,
        scrypt_salt_lenght=128,
        scrypt_lenght=512,
        scrypt_n=2**20,
        scrypt_r=8,
        scrypt_p=1,
        password_encoding="utf8",
        encryption_salt_lenght=128,
        pbkdf2_hash_algorithm=hashes.SHA3_512,
        pbkdf2_lenght=32,
        pbkdf2_iterations=1000000,
        encryption_algorithm=algorithms.AES,
        mode=modes.CBC,):

    all_data = fmt.read_formatted_encrypted_data(input_data)

    pass_storage_kdf = Scrypt(
        salt=all_data["digest_salt"],
        length=scrypt_lenght,
        n=scrypt_n,
        r=scrypt_r,
        p=scrypt_p
    )

    try:
        pass_storage_kdf.verify(
            bytes(password, encoding=password_encoding), all_data["digested_password"])
    except exceptions.InvalidKey:
        raise exceptions.InvalidKey(
            "The password you entered is wrong, or the encrypted file has been tampered with.")
    except Exception as exc:
        print(exc)
    decrypted = ed.decrypt(
        all_data["data"], password, all_data["encryption_salt"], all_data["iv"])

    return decrypted
