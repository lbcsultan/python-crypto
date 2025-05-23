def vigenere_encrypt(plaintext, key):
    result = []
    key = key.lower()
    key_len = len(key)
    key_idx = 0

    for ch in plaintext:
        if ch.isalpha():
            offset = ord('A') if ch.isupper() else ord('a')
            k = ord(key[key_idx % key_len]) - ord('a')
            enc = chr((ord(ch) - offset + k) % 26 + offset)
            result.append(enc)
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def vigenere_decrypt(ciphertext, key):
    result = []
    key = key.lower()
    key_len = len(key)
    key_idx = 0

    for ch in ciphertext:
        if ch.isalpha():
            offset = ord('A') if ch.isupper() else ord('a')
            k = ord(key[key_idx % key_len]) - ord('a')
            dec = chr((ord(ch) - offset - k + 26) % 26 + offset)
            result.append(dec)
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

# 사용 예시
plain = "flag{CiphersAreAwesome}"
key = "blorpy"

encrypted = vigenere_encrypt(plain, key)
decrypted = vigenere_decrypt(encrypted, key)

print("원문:", plain)
print("암호화:", encrypted)
print("복호화:", decrypted)
