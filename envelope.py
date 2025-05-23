import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def sign_message(private_key, message_bytes):
    h = SHA256.new(message_bytes)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(public_key, message_bytes, signature):
    h = SHA256.new(message_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_session_key(session_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key

def decrypt_session_key(enc_session_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    return session_key

def encrypt_message(session_key, message_bytes):
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message_bytes)
    return ciphertext, cipher_aes.nonce, tag

def decrypt_message(session_key, nonce, tag, ciphertext):
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    message_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return message_bytes

def main():
    print("1) 송신자 A, 수신자 B의 RSA 공개키/개인키 쌍 생성")
    priv_A, pub_A = generate_rsa_keypair()
    priv_B, pub_B = generate_rsa_keypair()
    print(" - 송신자 A 공개키:", pub_A.export_key().decode()[:100], "...")
    print(" - 수신자 B 공개키:", pub_B.export_key().decode()[:100], "...\n")

    # 송신자가 보낼 메시지
    message = "이것은 송신자 A가 수신자 B에게 보내는 비밀 메시지입니다."
    message_bytes = message.encode('utf-8')
    print("2) 송신자가 메시지를 전자서명하고, 세션키로 암호화, 세션키는 수신자 공개키로 암호화")
    print(" - 원문 메시지:", message)

    # 전자서명
    signature = sign_message(priv_A, message_bytes)
    print(" - 메시지 전자서명 생성 완료 (서명 길이: {} bytes)".format(len(signature)))

    # 세션키 생성 (AES 16바이트)
    session_key = get_random_bytes(16)
    print(" - AES 세션키 생성 (길이: 16 bytes)")

    # 메시지 암호화
    ciphertext, nonce, tag = encrypt_message(session_key, message_bytes)
    print(" - 메시지 AES 암호화 완료 (암호문 길이: {} bytes)".format(len(ciphertext)))

    # 세션키를 수신자 공개키로 암호화
    enc_session_key = encrypt_session_key(session_key, pub_B)
    print(" - 세션키를 수신자 B 공개키로 암호화 완료 (암호화된 세션키 길이: {} bytes)\n".format(len(enc_session_key)))

    # 전자봉투 JSON 생성
    envelope = {
        "enc_session_key": enc_session_key.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": signature.hex(),
        "sender_public_key": pub_A.export_key().decode()  # 수신자가 서명 검증 위해 공개키 포함
    }
    envelope_json = json.dumps(envelope, indent=2, ensure_ascii=False)
    print("3) 전자봉투(JSON) 생성 완료:")
    print(envelope_json, "\n")

    print("4) 수신자 B가 전자봉투 수신 후 처리 시작")
    # 수신자 B가 전자봉투 파싱
    received = json.loads(envelope_json)

    # 암호화된 세션키 복호화
    enc_sess_key_bytes = bytes.fromhex(received["enc_session_key"])
    session_key_dec = decrypt_session_key(enc_sess_key_bytes, priv_B)
    print(" - 세션키 복호화 완료")

    # 암호문, nonce, tag 복호화
    ciphertext_bytes = bytes.fromhex(received["ciphertext"])
    nonce_bytes = bytes.fromhex(received["nonce"])
    tag_bytes = bytes.fromhex(received["tag"])
    message_decrypted = decrypt_message(session_key_dec, nonce_bytes, tag_bytes, ciphertext_bytes)
    print(" - 메시지 복호화 완료")

    # 서명 검증
    signature_bytes = bytes.fromhex(received["signature"])
    sender_pub_key = RSA.import_key(received["sender_public_key"].encode())
    is_valid = verify_signature(sender_pub_key, message_decrypted, signature_bytes)
    print(" - 전자서명 검증 결과:", "유효함" if is_valid else "유효하지 않음")

    # 최종 메시지 출력
    print(" - 복호화된 메시지:", message_decrypted.decode('utf-8'))

if __name__ == "__main__":
    main()
