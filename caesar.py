def caesar_encrypt(plaintext, shift):
    result = ""
    for ch in plaintext:
        if ch.isupper():
            # 대문자 처리
            result += chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))
        elif ch.islower():
            # 소문자 처리
            result += chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))
        else:
            # 공백, 숫자, 특수문자 등은 그대로
            result += ch
    return result

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# 사용 예시
text = "Hello, Caesar Cipher! 123"
shift = 3

encrypted = caesar_encrypt(text, shift)
decrypted = caesar_decrypt(encrypted, shift)

print("원문:", text)
print("암호화:", encrypted)
print("복호화:", decrypted)
