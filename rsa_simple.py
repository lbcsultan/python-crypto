import random

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(min_value, max_value):
    prime = random.randint(min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def generate_keypair():
    p = generate_prime(10, 100)
    q = generate_prime(10, 100)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = random.randint(1, phi)
    while not (is_prime(e) and e < phi):
        e = random.randint(1, phi)
    
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

def decrypt(private_key, ciphertext):
    d, n = private_key
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plain)

# 키 생성 및 출력
public_key, private_key = generate_keypair()
print("Public Key (e, n):", public_key)
print("Private Key (d, n):", private_key)

# 메시지 암호화 및 복호화
message = "Hello, RSA!"
encrypted_msg = encrypt(public_key, message)
decrypted_msg = decrypt(private_key, encrypted_msg)

print("\nOriginal message:", message)
print("Encrypted message:", encrypted_msg)
print("Decrypted message:", decrypted_msg)
