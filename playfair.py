import string

def create_table(key):
    key = key.upper().replace('J', 'I')
    result = []
    for c in key:
        if c not in result and c in string.ascii_uppercase:
            result.append(c)
    for c in string.ascii_uppercase:
        if c == 'J':
            continue
        if c not in result:
            result.append(c)
    table = [result[i*5:(i+1)*5] for i in range(5)]
    return table

def find_position(table, char):
    for i in range(5):
        for j in range(5):
            if table[i][j] == char:
                return i, j
    return None

def prepare_text(text):
    text = text.upper().replace('J', 'I')
    prepared = ''
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            prepared += a + 'X'
            i += 1
        else:
            prepared += a + b
            i += 2
    if len(prepared) % 2 != 0:
        prepared += 'X'
    return prepared

def playfair_encrypt(plaintext, key):
    table = create_table(key)
    plaintext = ''.join([c for c in plaintext.upper() if c in string.ascii_uppercase])
    plaintext = prepare_text(plaintext)
    ciphertext = ''
    for i in range(0, len(plaintext), 2):
        a, b = plaintext[i], plaintext[i+1]
        row1, col1 = find_position(table, a)
        row2, col2 = find_position(table, b)
        if row1 == row2:
            ciphertext += table[row1][(col1+1)%5]
            ciphertext += table[row2][(col2+1)%5]
        elif col1 == col2:
            ciphertext += table[(row1+1)%5][col1]
            ciphertext += table[(row2+1)%5][col2]
        else:
            ciphertext += table[row1][col2]
            ciphertext += table[row2][col1]
    return ciphertext

def playfair_decrypt(ciphertext, key):
    table = create_table(key)
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i+1]
        row1, col1 = find_position(table, a)
        row2, col2 = find_position(table, b)
        if row1 == row2:
            plaintext += table[row1][(col1-1)%5]
            plaintext += table[row2][(col2-1)%5]
        elif col1 == col2:
            plaintext += table[(row1-1)%5][col1]
            plaintext += table[(row2-1)%5][col2]
        else:
            plaintext += table[row1][col2]
            plaintext += table[row2][col1]
    return plaintext

# 사용 예시
key = "CRYPTO"
plaintext = "HELLO WORLD"

# 전처리(공백, 특수문자 제거, I/J 처리, 쌍 만들기)
prepared_plaintext = ''.join([c for c in plaintext.upper() if c in string.ascii_uppercase])
prepared_plaintext = prepare_text(prepared_plaintext)

ciphertext = playfair_encrypt(plaintext, key)
decrypted = playfair_decrypt(ciphertext, key)

print("평문:", prepared_plaintext)
print("암호문:", ciphertext)
print("복호화평문:", decrypted)
