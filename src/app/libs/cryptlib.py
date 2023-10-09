import base64
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

"""
This class serves the purpose of encrypting and decrypting data using a specified key,
which in this case is the Flask secret key.

It is currently used to encrypt user API keys and subsequently decrypt them when
necessary to retrieve the user API key.  In contrast, for passwords, the use of
hashing alone suffices because we never need to recover the user's plaintext password.
However, with API keys, if we intend to display the API key to the user, we must
have a method to decrypt it.

This class employs ECB encryption, meaning that when the same data and secret
key are used, the resulting ciphertext will always be the same.
While technically less secure than CBC or GCM encryption methods,
this characteristic allows us to identify a user solely based on their API key.
"""


class CryptLib:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()

    def pkcs7_pad(self, data):
        block_size = 16
        padding_size = block_size - len(data) % block_size
        return data + bytes([padding_size] * padding_size)

    def pkcs7_unpad(self, data):
        return data[: -data[-1]]

    def encrypt(self, data):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        original_data = data.encode("utf-8")
        hash_of_original = hashlib.sha256(original_data).digest()
        padded_data = self.pkcs7_pad(original_data)
        ciphered_data = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphered_data + hash_of_original).decode("utf-8")

    def decrypt(self, data):
        original_hash = base64.b64decode(data)[-32:]
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_and_hash = (
            decryptor.update(base64.b64decode(data)) + decryptor.finalize()
        )
        decrypted_data = decrypted_and_hash[:-32]
        decrypted_unpadded_data = self.pkcs7_unpad(decrypted_data)
        computed_hash = hashlib.sha256(decrypted_unpadded_data).digest()

        if original_hash != computed_hash:
            raise ValueError(
                "Decryption failed, "
                "The application secret key is either incorrect "
                "or the data has been tampered with!"
            )

        return decrypted_unpadded_data.decode("utf-8")
