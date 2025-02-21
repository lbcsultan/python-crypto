from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512

def hash_input(input_data):
    hash_functions = [MD5, SHA1, SHA224, SHA256, SHA384, SHA512]
    
    for hash_func in hash_functions:
        h = hash_func.new()
        h.update(input_data.encode('utf-8'))
        print(f"{hash_func.__name__}: {h.hexdigest()}")

def main():
    while True:
        user_input = input("해시할 문자열을 입력하세요 (종료하려면 'q' 입력): ")
        if user_input.lower() == 'q':
            break
        print("\n해시 결과:")
        hash_input(user_input)
        print()

if __name__ == "__main__":
    main()
