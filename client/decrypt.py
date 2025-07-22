import os
import getpass
import hashlib
from shared.crypto_utils import (
    aes_decrypt_with_psk, rsa_decrypt, aes_decrypt
)
from shared.ciphers import (
    caesar_decrypt,
    atbash,
    vigenere_decrypt,
    vernam_decrypt,
    transpose_decrypt
)

RSA_PRIVATE_KEY_FILE = "client/private.pem"

def main():
    # Step 1: Ask for encrypted file path
    file_path = input("📂 Enter path to the encrypted file: ").strip()
    if not os.path.exists(file_path):
        print("❌ File not found.")
        return

    # Step 2: Ask for PSK
    psk = getpass.getpass("🔑 Enter pre-shared key (PSK): ").encode()

    # Step 3: Read encrypted file content
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    # Step 4: Outer decryption with PSK
    try:
        decrypted_package = aes_decrypt_with_psk(encrypted_data, psk)
        print("✅ Outer layer decrypted with PSK")
    except Exception:
        print("❌ Failed to decrypt with PSK. Wrong PSK or corrupted file.")
        return

    # Step 5: Parse decrypted package
    try:
        offset = 0
        filename_len = int.from_bytes(decrypted_package[offset:offset+2], 'big')
        offset += 2
        filename = decrypted_package[offset:offset+filename_len].decode()
        offset += filename_len

        aes_key_len = int.from_bytes(decrypted_package[offset:offset+2], 'big')
        offset += 2
        encrypted_aes_key = decrypted_package[offset:offset+aes_key_len]
        offset += aes_key_len

        newline_idx = decrypted_package.index(b'\n', offset)
        original_hash = decrypted_package[offset:newline_idx].decode()
        offset = newline_idx + 1

        aes_encrypted_content = decrypted_package[offset:]
    except Exception:
        print("❌ Failed to parse decrypted package.")
        return

    # Step 6: Decrypt AES key
    if not os.path.exists(RSA_PRIVATE_KEY_FILE):
        print("❌ Missing RSA private key.")
        return

    with open(RSA_PRIVATE_KEY_FILE, 'rb') as keyf:
        private_key = keyf.read()

    try:
        aes_key = rsa_decrypt(encrypted_aes_key, private_key)
    except Exception:
        print("❌ Failed to decrypt AES key with RSA.")
        return

    # Step 7: Decrypt AES file content
    try:
        classical_cipher_text = aes_decrypt(aes_encrypted_content, aes_key).decode('utf-8')
    except Exception:
        print("❌ Failed to decrypt file content with AES.")
        return

    # Step 8: Classical cipher decryption chain
    try:
        step1 = transpose_decrypt(classical_cipher_text)
        step2 = vernam_decrypt(step1, "SECRET")
        step3 = vigenere_decrypt(step2, "KEY")
        step4 = atbash(step3)
        plaintext = caesar_decrypt(step4, 3)
    except Exception:
        print("❌ Classical cipher decryption failed. Possibly corrupted file.")
        return

    # Step 9: Overwrite original file with decrypted content
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(plaintext)

    print(f"✅ File successfully decrypted and restored: {file_path}")

    # Step 10: Verify and show hashes
    computed_hash = hashlib.md5(plaintext.encode('utf-8')).hexdigest()

    print("\n🔎 MD5 Hash Verification:")
    print(f"📦 Original Hash : {original_hash}")
    print(f"🧮 Computed Hash : {computed_hash}")

    if computed_hash == original_hash:
        print("✅ File integrity verified. Hashes match.")
    else:
        print("⚠️ Warning: Hash mismatch! File may be corrupted or tampered.")

if __name__ == '__main__':
    main()
