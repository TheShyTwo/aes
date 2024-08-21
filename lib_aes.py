from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
from Crypto.Random import get_random_bytes

def read_file(file_path):
    with open(file_path,'r',encoding='utf-8') as file:
        plaintext = file.read()
    return plaintext

def create_key(length_key):
    return get_random_bytes(length_key)

def hex_to_bit(hex_string):
    byte_data = binascii.unhexlify(hex_string)
    bit_data = ''.join(format(byte, '08b') for byte in byte_data)
    return bit_data

def bit_to_hex(bit_string):
    byte_data = bytes(int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8))
    hex_data = binascii.hexlify(byte_data).decode()
    return hex_data

def encrypt_cbc(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    hex_encrypted_data = iv.hex() + encrypted_data.hex() 
    bit_encrypted_data = hex_to_bit(hex_encrypted_data) 
    return bit_encrypted_data

def decrypt_cbc(bit_encrypted_data, key):
    hex_encrypted_data = bit_to_hex(bit_encrypted_data)
    iv = bytes.fromhex(hex_encrypted_data[:32])
    ciphertext = bytes.fromhex(hex_encrypted_data[32:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data.decode()


def encrypt_cfb(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_data = cipher.encrypt(plaintext.encode())
    hex_encrypted_data = iv.hex() + encrypted_data.hex() 
    bit_encrypted_data = hex_to_bit(hex_encrypted_data) 
    return bit_encrypted_data

def decrypt_cfb(bit_encrypted_data, key):
    hex_encrypted_data = bit_to_hex(bit_encrypted_data)
    iv = bytes.fromhex(hex_encrypted_data[:32])
    ciphertext = bytes.fromhex(hex_encrypted_data[32:])
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.decode()

def encrypt_ctr(plaintext, key):
    nonce = get_random_bytes(AES.block_size // 2)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    encrypted_data = cipher.encrypt(plaintext.encode())
    hex_encrypted_data = nonce.hex() + encrypted_data.hex() 
    bit_encrypted_data = hex_to_bit(hex_encrypted_data) 
    return bit_encrypted_data

def decrypt_ctr(bit_encrypted_data, key):
    hex_encrypted_data = bit_to_hex(bit_encrypted_data)
    nonce = bytes.fromhex(hex_encrypted_data[:16])  # Use half the length for the nonce
    ciphertext = bytes.fromhex(hex_encrypted_data[16:])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.decode()

def encrypt_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plaintext.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    hex_encrypted_data = encrypted_data.hex() 
    bit_encrypted_data = hex_to_bit(hex_encrypted_data) 
    return bit_encrypted_data

def decrypt_ecb(bit_encrypted_data, key):
    hex_encrypted_data = bit_to_hex(bit_encrypted_data)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(bytes.fromhex(hex_encrypted_data))
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data.decode()


def encrypt_ofb(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    encrypted_data = cipher.encrypt(plaintext.encode())
    hex_encrypted_data = iv.hex() + encrypted_data.hex() 
    bit_encrypted_data = hex_to_bit(hex_encrypted_data) 
    return bit_encrypted_data

def decrypt_ofb(bit_encrypted_data, key):
    hex_encrypted_data = bit_to_hex(bit_encrypted_data)
    iv = bytes.fromhex(hex_encrypted_data[:32])
    ciphertext = bytes.fromhex(hex_encrypted_data[32:])
    cipher = AES.new(key, AES.MODE_OFB, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.decode()



file_path = 'text.txt'
plaintext = read_file(file_path)

# Tạo khóa ngẫu nhiên
key_length = 32  # 128-bit key
key = create_key(key_length)

# Mã hóa dữ liệu
encrypted_data = encrypt_ofb(plaintext, key)
print(len(encrypted_data))
# Giải mã dữ liệu
decrypted_data = decrypt_ofb(encrypted_data, key)
print("Decrypted data:", decrypted_data)