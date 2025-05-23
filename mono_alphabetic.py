import string

# 알파벳과 임의의 치환표(키)
plain_alphabet = string.ascii_lowercase
cipher_alphabet = "jnahiuvrylzmbfcsqtdeogpwxk"  # 예시 키 (26자, 중복 없이 섞기)

def encrypt(plaintext):
    result = []
    for ch in plaintext:
        if ch.islower():
            idx = plain_alphabet.find(ch)
            result.append(cipher_alphabet[idx])
        elif ch.isupper():
            idx = plain_alphabet.upper().find(ch)
            result.append(cipher_alphabet[idx].upper())
        else:
            result.append(ch)
    return ''.join(result)

def decrypt(ciphertext):
    result = []
    for ch in ciphertext:
        if ch.islower():
            idx = cipher_alphabet.find(ch)
            result.append(plain_alphabet[idx])
        elif ch.isupper():
            idx = cipher_alphabet.upper().find(ch)
            result.append(plain_alphabet[idx].upper())
        else:
            result.append(ch)
    return ''.join(result)

# 사용 예시
text = "I! am manseon"
enc = encrypt(text)
dec = decrypt(enc)

print("원문:", text)
print("암호화:", enc)
print("복호화:", dec)
