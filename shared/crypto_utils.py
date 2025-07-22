import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

import hashlib

def md5_hash_from_string(content: str) -> str:
    return hashlib.md5(content.encode('utf-8')).hexdigest()


# MD5 hash for file
def md5_hash(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Generate AES-256 key
def generate_aes_key():
    return get_random_bytes(32)

# AES encryption (CBC)
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

# AES decryption (CBC)
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Encrypt AES key with RSA public key
def rsa_encrypt(data, public_key_bytes):
    pub_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    return cipher_rsa.encrypt(data)

# Decrypt AES key with RSA private key
def rsa_decrypt(data, private_key_bytes):
    priv_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    return cipher_rsa.decrypt(data)

# PSK-based AES encryption (wrap the final package)
def aes_encrypt_with_psk(data: bytes, psk: bytes) -> bytes:
    key = sha256(psk).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

# PSK-based AES decryption (unwrap the package)
def aes_decrypt_with_psk(ciphertext: bytes, psk: bytes) -> bytes:
    key = sha256(psk).digest()
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)
