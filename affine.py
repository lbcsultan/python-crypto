def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    # a의 m에 대한 곱셈 역원 계산 (확장 유클리드 알고리즘)
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("역원이 존재하지 않습니다.")

def affine_encrypt(plaintext, a, b):
    result = ''
    for char in plaintext:
        if char.isalpha():
            x = ord(char.lower()) - ord('a')
            enc = (a * x + b) % 26
            cipher_char = chr(enc + ord('a'))
            result += cipher_char.upper() if char.isupper() else cipher_char
        else:
            result += char
    return result

def affine_decrypt(ciphertext, a, b):
    result = ''
    a_inv = modinv(a, 26)
    for char in ciphertext:
        if char.isalpha():
            y = ord(char.lower()) - ord('a')
            dec = (a_inv * (y - b)) % 26
            plain_char = chr(dec + ord('a'))
            result += plain_char.upper() if char.isupper() else plain_char
        else:
            result += char
    return result

# 사용 예시
a, b = 5, 8  # a는 26과 서로소여야 함 (예: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)
plaintext = "Affine Cipher Example!"
ciphertext = affine_encrypt(plaintext, a, b)
decrypted = affine_decrypt(ciphertext, a, b)

print("원문:", plaintext)
print("암호문:", ciphertext)
print("복호문:", decrypted)
