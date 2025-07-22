# Caesar Cipher
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Atbash Cipher
def atbash(text):
    result = ""
    for char in text:
        if char.isupper():
            result += chr(90 - (ord(char) - 65))
        elif char.islower():
            result += chr(122 - (ord(char) - 97))
        else:
            result += char
    return result

# Vigenère Cipher
def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset + shift) % 26 + offset)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset - shift) % 26 + offset)
            key_index += 1
        else:
            result += char
    return result

# Vernam Cipher (XOR)
def vernam_encrypt(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def vernam_decrypt(cipher, key):
    return vernam_encrypt(cipher, key)  # Symmetric

# Transposition Cipher (simple reversible using reverse)
def transpose_encrypt(text):
    return text[::-1]

def transpose_decrypt(text):
    return text[::-1]
