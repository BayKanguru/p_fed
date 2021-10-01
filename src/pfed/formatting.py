"""Functions to format data for saving and reusing."""


def format_encrypted_data(data: bytes, iv: bytes, encryption_salt: bytes, digest_salt: bytes, digested_password: bytes) -> bytes:
    """Formats data, iv, salts and digested_password in a bytes object.
    digested_password is used for checking if password is correct in 
    decryption.
    """
    p_hash_lenght = len(digested_password).to_bytes(32, "big")
    formatted_data = p_hash_lenght + iv + encryption_salt + \
        digest_salt + digested_password + data
    return formatted_data


def read_formatted_encrypted_data(formatted_data: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Splits formatted_data into its components.  Used for decryption."""
    hash_lenght = int.from_bytes(formatted_data[:32], "big")
    iv = formatted_data[32:48]
    encryption_salt = formatted_data[48:176]
    digest_salt = formatted_data[176:304]
    digested_password = formatted_data[304:304+hash_lenght]
    data = formatted_data[304+hash_lenght:]
    return digested_password, encryption_salt, digest_salt, iv, data
