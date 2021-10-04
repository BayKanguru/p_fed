"""Functions to format data for saving and reusing."""
from cryptography.hazmat.primitives import padding


def format_encrypted_data(
        data: bytes,
        encryption_salt: bytes,
        digest_salt: bytes,
        digested_password: bytes,
        iv: bytes = None,
        encryption_nonce=None,
        mode_nonce=None,
        mode_tweak=None) -> bytes:
    """Formats data, iv, salts and digested_password in a bytes object.
    digested_password is used for checking if password is correct in 
    decryption.
    """
    def pad(data, block_size):
        padder = padding.PKCS7(block_size).padder()
        return padder.update(data) + padder.finalize()

    stored_data_list = ""
    stored_data = b""
    if iv is not None:
        stored_data_list += "iv-"
        stored_data += pad(iv, 256)
    if encryption_nonce is not None:
        stored_data_list += "en-"
        stored_data += pad(encryption_nonce, 256)
    if mode_nonce is not None:
        stored_data_list += "mn-"
        stored_data += pad(mode_nonce, 256)
    if mode_tweak is not None:
        stored_data_list += "mt-"
        stored_data += pad(mode_tweak, 256)

    if stored_data_list == "":
        raise ValueError(
            "you should supply iv,nonce or tweak info about the encryption process")

    stored_data_list_b = stored_data_list.encode("utf8")
    stored_data_list_len = len(stored_data_list_b).to_bytes(32, "big")
    p_hash_lenght = len(digested_password).to_bytes(32, "big")

    formatted_data = stored_data_list_len + stored_data_list_b + stored_data + p_hash_lenght + encryption_salt + \
        digest_salt + digested_password + data
    return formatted_data


def read_formatted_encrypted_data(formatted_data: bytes) -> tuple:
    """Splits formatted_data into its components.  Used for decryption."""
    def unpad(data, block_size):
        unpadder = padding.PKCS7(block_size).unpadder()
        return unpadder.update(data) + unpadder.finalize()

    stored_data_list_len = int.from_bytes(formatted_data[:32], "big")
    stored_data_list_s = str(
        formatted_data[32:32+stored_data_list_len], encoding="utf8")
    stored_data_list = stored_data_list_s.split("-")
    stored_data_list = [s for s in stored_data_list if s]

    stored_data = formatted_data[32 +
                                 stored_data_list_len:
                                 32 +
                                 stored_data_list_len +
                                 len(stored_data_list)*32]
    for i, data in enumerate(stored_data_list):
        data_dict = {}
        data_dict[data] = unpad(stored_data[i*32:(i+1)*32], 256)

    formatted_data = formatted_data[32
                                    + stored_data_list_len
                                    + len(stored_data_list) * 32:]
    hash_lenght = int.from_bytes(formatted_data[:32], "big")
    encryption_salt = formatted_data[32:160]
    digest_salt = formatted_data[160:288]
    digested_password = formatted_data[288:288+hash_lenght]
    data = formatted_data[288+hash_lenght:]

    un_formatted_data = {
        "hash_lenght": hash_lenght,
        "encryption_salt": encryption_salt,
        "digest_salt": digest_salt,
        "digested_password": digested_password,
        "data": data
    }
    un_formatted_data.update(data_dict)
    return un_formatted_data
