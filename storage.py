"""
Storage of data
"""


def save_encrypted(file_path, data, iv, digested_password):
    """Save the encrypted data, iv with hashed password
    """
    p_hash_lenght = len(digested_password).to_bytes(32, "big")
    with open(file_path, "wb") as f:
        f.write(p_hash_lenght + iv + digested_password + data)


def read_encrypted(file_path):
    """Read encrypted data and iv
    """
    with open(file_path, "rb") as f:
        content = f.read()
        hash_lenght = int.from_bytes(content[:32], "big")
        iv = content[32:48]
        digested_password = content[48:48+hash_lenght]
        data = content[48+hash_lenght:]
    return digested_password, iv, data
