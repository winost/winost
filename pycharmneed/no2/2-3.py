import os
from Crypto.Cipher import AES

# --- Padding Exception ---
class PaddingException(Exception):
    pass

# --- PKCS#7 Padding ---
def pkcs7_pad(data, block_size):
    pad_length = block_size - len(data) % block_size
    padding = bytes([pad_length] * pad_length)
    return data + padding

def pkcs7_unpad(data):
    pad_length = data[-1]
    if pad_length < 1 or pad_length > len(data):
        raise PaddingException("Invalid padding length.")
    if data[-pad_length:] != bytes([pad_length] * pad_length):
        raise PaddingException("Invalid padding bytes.")
    return data[:-pad_length]

# --- XOR for CBC ---
def fixed_xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

def ecb_encrypt(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def ecb_decrypt(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)

# --- CBC Encryption ---
def cbc_encrypt(plaintext, key, iv):
    block_size = len(key)
    padded_plaintext = pkcs7_pad(plaintext, block_size)
    ciphertext = b''
    previous_block = iv
    for i in range(0, len(padded_plaintext), block_size):
        plaintext_block = padded_plaintext[i:i + block_size]
        xored_block = fixed_xor(plaintext_block, previous_block)
        encrypted_block = ecb_encrypt(xored_block, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    block_size = len(key)
    decrypted_text = b''
    previous_block = iv
    for i in range(0, len(ciphertext), block_size):
        ciphertext_block = ciphertext[i:i + block_size]
        decrypted_block = ecb_decrypt(ciphertext_block, key)
        decrypted_text += fixed_xor(decrypted_block, previous_block)
        previous_block = ciphertext_block
    try:
        return pkcs7_unpad(decrypted_text)
    except PaddingException:
        raise ValueError("Invalid padding")

# --- Input Sanitization & Oracle ---
random_key = os.urandom(16)

def sanitize_input(user_input):
    return user_input.replace(";", "%3B").replace("=", "%3D")

def encryption_oracle(user_input):
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    sanitized_input = sanitize_input(user_input)
    plaintext = (prefix + sanitized_input + suffix).encode('utf-8')
    iv = os.urandom(16)
    return cbc_encrypt(plaintext, random_key, iv), iv

def is_admin(ciphertext, iv):
    decrypted_text = cbc_decrypt(ciphertext, random_key, iv)
    print("解密后的明文:")
    try:
        print(decrypted_text.decode('utf-8', errors='replace'))
    except Exception as e:
        print("明文解码失败:", e)
    return b";admin=true;" in decrypted_text

# --- Bit-Flipping Attack ---
def bitflip_attack(ciphertext, block_size):
    # block_to_modify = 2 (third block, zero-indexed)
    block_to_modify = 2
    target = b";admin=true;"
    target_block = bytearray(target.ljust(block_size, b'\x00'))
    modified_ciphertext = bytearray(ciphertext)
    # Assume original user input is "B"*block_size + "admin=true"
    for i in range(block_size):
        # Flip the byte in previous block to achieve target after decryption
        modified_ciphertext[block_size * (block_to_modify - 1) + i] ^= target_block[i] ^ ord("B")
    return bytes(modified_ciphertext)

# --- Test the Attack ---
if __name__ == "__main__":
    # Craft user input so ";admin=true;" falls at the start of the third block
    user_input = "B" * 16 + "admin=true"
    ciphertext, iv = encryption_oracle(user_input)
    modified_ciphertext = bitflip_attack(ciphertext, 16)
    print("是否获得admin权限:", is_admin(modified_ciphertext, iv))