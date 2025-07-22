import os
import getpass
from shared.crypto_utils import (
    md5_hash_from_string, generate_aes_key, aes_encrypt, rsa_encrypt, aes_encrypt_with_psk
)
from shared.ciphers import (
    caesar_encrypt, atbash, vigenere_encrypt, vernam_encrypt, transpose_encrypt
)

RSA_PUBLIC_KEY_FILE = "client/public.pem"

def main():
    file_path = input("📂 Enter path to the file you want to encrypt: ").strip()
    if not os.path.exists(file_path):
        print("❌ File not found.")
        return

    psk = getpass.getpass("🔑 Enter pre-shared key (PSK): ").encode()

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            plaintext = f.read()
    except:
        print("❌ Only readable text files are supported.")
        return

    if not plaintext.strip():
        print("❌ File is empty. Aborting.")
        return

    file_hash = md5_hash_from_string(plaintext)
    print(f"🔍 MD5 Hash: {file_hash}")

    # Classical layer
    step1 = caesar_encrypt(plaintext, 3)
    step2 = atbash(step1)
    step3 = vigenere_encrypt(step2, "KEY")
    step4 = vernam_encrypt(step3, "SECRET")
    final_cipher = transpose_encrypt(step4)

    aes_key = generate_aes_key()
    aes_encrypted = aes_encrypt(final_cipher.encode(), aes_key)

    if not os.path.exists(RSA_PUBLIC_KEY_FILE):
        print("❌ Missing RSA public key.")
        return
    with open(RSA_PUBLIC_KEY_FILE, 'rb') as pubf:
        public_key = pubf.read()

    encrypted_aes_key = rsa_encrypt(aes_key, public_key)

    filename_bytes = os.path.basename(file_path).encode()
    package = b""
    package += len(filename_bytes).to_bytes(2, 'big')
    package += filename_bytes
    package += len(encrypted_aes_key).to_bytes(2, 'big')
    package += encrypted_aes_key
    package += file_hash.encode() + b"\n"
    package += aes_encrypted

    fully_encrypted = aes_encrypt_with_psk(package, psk)

    with open(file_path, 'wb') as f:
        f.write(fully_encrypted)

    print(f"✅ File encrypted in-place: {file_path}")

if __name__ == '__main__':
    main()
