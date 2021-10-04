import getpass
import pathlib
import secrets
import argparse
import datetime

from cryptography import exceptions

import pfed.full_process as full


def run():
    """Starts the command-line inteface."""

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

    # positional arguments
    parser.add_argument(
        "input_file", help="the file you want to run operations on", type=str)

    args = parser.parse_args()

    if args.encrypt:
        password = getpass.getpass("Password:\n")
        repeated_password = getpass.getpass("Repeat password:\n")

        with open(args.input_file, "rb") as file:
            data = file.read()

        iv = secrets.token_bytes(16)
        encrypted = full.encrypt_and_prepare(
            password,
            repeated_password,
            data,
            iv=iv)

        if args.output is None:
            with open(args.input_file, "wb") as file:
                file.write(encrypted)
        else:
            with open(args.output, "wb") as file:
                file.write(encrypted)

    elif args.decrypt:
        password = getpass.getpass("Password:\n")

        current_file = str(pathlib.Path(__file__).parent.resolve())

        with open(args.input_file, "rb") as file:
            formatted_data = file.read()

        try:
            decrypted = full.decrypt_and_prepare(password, formatted_data)
        except exceptions.InvalidKey:
            with open(current_file + "/logs/wrong_pass.log", "a") as file:
                file.write(
                    "[time:{}][file:{}]: wrong password\n".format(
                        datetime.datetime.now().isoformat(), args.input_file))

        if args.output is None:
            with open(args.input_file, "wb") as file:
                file.write(decrypted)
        else:
            with open(args.output, "wb") as file:
                file.write(decrypted)


if __name__ == "__main__":
    run()
