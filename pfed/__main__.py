import os
import sys
import getpass
import pathlib
import datetime
import argparse

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import pfed.enc_dec as ed
import pfed.formatting as fmt


def run():
    """Starts the command-line inteface."""

    # initial values
    encryptable = True
    decryptable = True

    # parser setup
    parser = argparse.ArgumentParser(
        prog="p_fed", description="Password File Encryptor/Decryptor")

    # optional arguments
    operations = parser.add_mutually_exclusive_group(required=True)

    operations.add_argument("-e", "--encrypt",
                            help="encrypts the file", action="store_true")
    operations.add_argument("-d", "--decrypt",
                            help="decrypts the file", action="store_true")

    parser.add_argument("-o", "--output",
                        help="specify the output file", type=str)
    parser.add_argument("-v", "--verbosity", action="count", default=0,
                        help="increase output verbosity")

    # positional arguments
    parser.add_argument(
        "input_file", help="the file you want to run operations on", type=str)

    args = parser.parse_args()

    verbosity = args.verbosity if args.verbosity <= 2 else 2  # to limit verbosity

    if args.encrypt:
        password = getpass.getpass("Password:\n")
        repeated_password = getpass.getpass("Repeat password:\n")

        if not password == repeated_password:
            encryptable = False
            print("passwords are not the same, did not encrypt.")
        elif verbosity == 1:
            print("password == repeated_password")
        elif verbosity == 2:
            print("password and repeated_password are the same, encrypting...")

        if encryptable:
            iv = os.urandom(16)

            ps_kdf_salt = os.urandom(128)
            ps_kdf = Scrypt(
                salt=ps_kdf_salt,
                length=512,
                n=2**20,
                r=8,
                p=1
            )

            password_digested = ps_kdf.derive(bytes(password, encoding="utf8"))
            if verbosity == 1:
                print("password has been digested")
            elif verbosity == 2:
                print("derived key for password using Scrypt for password storage")

            with open(args.input_file, "rb") as f:
                data = f.read()

            encryption_salt = os.urandom(128)
            encrypted = ed.encrypt(
                data, password, encryption_salt, iv)
            if verbosity == 1:
                print("file encrypted")
            elif verbosity == 2:
                print("file encryption completed using AES256")

            formatted_data = fmt.format_encrypted_data(
                encrypted,
                iv,
                encryption_salt,
                ps_kdf_salt,
                password_digested)
            if args.output is None:
                with open(args.input_file, "wb") as f:
                    f.write(formatted_data)
            else:
                with open(args.output, "wb") as f:
                    f.write(formatted_data)

    elif args.decrypt:
        password = getpass.getpass("Password:\n")

        current_file = str(pathlib.Path(__file__).parent.resolve())

        with open(args.input_file, "rb") as f:
            formatted_data = f.read()
        d_password, e_salt, d_salt, iv_r, enc_data = fmt.read_formatted_encrypted_data(
            formatted_data)

        ps_kdf = Scrypt(
            salt=d_salt,
            length=512,
            n=2**20,
            r=8,
            p=1
        )

        try:
            ps_kdf.verify(bytes(password, encoding="utf8"), d_password)
        except exceptions.InvalidKey:
            print(
                "The password you entered is wrong, or the encrypted file has been tampered with.")
            decryptable = False
        else:
            if verbosity == 1:
                print("correct password")
            elif verbosity == 2:
                print("correct password has been entered, decrypting...")

        if decryptable:
            decrypted = ed.decrypt(
                enc_data, password, e_salt, iv_r)

            if args.output is None:
                with open(args.input_file, "wb") as f:
                    f.write(decrypted)
            else:
                with open(args.output, "wb") as f:
                    f.write(decrypted)
        else:
            with open(current_file + "/logs/log.log", "a") as f:
                f.write(
                    "[time:{}][file:{}]: wrong password\n".format(datetime.datetime.now().isoformat(), args.input_file))


if __name__ == "__main__":
    run()
