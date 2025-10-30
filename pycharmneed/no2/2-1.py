import random
from base64 import b64decode
from Crypto.Cipher import AES

BLOCK_SIZE = 16
KEY = bytes([random.randint(0, 255) for _ in range(16)])
UNKNOWN_STRING = b64decode(
    b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    b"YnkK"
)
PREFIX = bytes([random.randint(0, 255) for _ in range(random.randint(5, 30))])  # 支持多于一个块

def pkcs7_pad(data, block_size):
    pad_length = block_size - len(data) % block_size
    return data + bytes([pad_length] * pad_length)

def pkcs7_unpad(data):
    if not data:
        return b''
    pad_length = data[-1]
    if pad_length < 1 or pad_length > BLOCK_SIZE:
        return data
    if data[-pad_length:] != bytes([pad_length] * pad_length):
        return data
    return data[:-pad_length]

def ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data, BLOCK_SIZE))

def encryption_oracle(data):
    return ecb_encrypt(PREFIX + data + UNKNOWN_STRING, KEY)

def detect_block_size(oracle):
    base = len(oracle(b""))
    for i in range(1, 64):
        test = len(oracle(b"A" * i))
        if test > base:
            return test - base
    raise Exception("块大小检测失败")

def find_prefix_alignment(oracle, block_size):
    # 尝试不同长度填充，使得密文有两个连续块内容完全相同
    marker = b"A" * (block_size * 2)
    for pad_len in range(block_size * 2):
        test_input = b"B" * pad_len + marker
        ct = oracle(test_input)
        blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                # i为第一个可控块索引，pad_len为需要填充的长度
                return pad_len, i
    raise Exception("无法对齐前缀块")

def decrypt_ecb_with_random_prefix(oracle):
    block_size = detect_block_size(oracle)
    print(f"Detected block size: {block_size}")

    pad_len, controlled_block_index = find_prefix_alignment(oracle, block_size)
    print(f"Prefix alignment pad length: {pad_len}, Controlled block index: {controlled_block_index}")

    total_len = len(UNKNOWN_STRING)

    recovered = b""
    for i in range(total_len):
        # 计算填充长度，使得爆破字节处于可控块末尾
        pad = b"B" * pad_len + b"A" * (block_size - (len(recovered) % block_size) - 1)
        block_num = controlled_block_index + (len(recovered) // block_size)
        ct = oracle(pad)
        target_block = ct[block_num * block_size : (block_num + 1) * block_size]
        block_dict = {}
        for b in range(256):
            guess = pad + recovered + bytes([b])
            guess_ct = oracle(guess)
            guess_block = guess_ct[block_num * block_size : (block_num + 1) * block_size]
            block_dict[guess_block] = b
        val = block_dict.get(target_block, None)
        if val is None:
            print(f"爆破失败，已恢复内容: {recovered}")
            break
        recovered += bytes([val])
    # 输出解密内容（去除PKCS7填充）
    try:
        result = pkcs7_unpad(recovered).decode()
    except Exception as e:
        result = recovered.decode(errors="ignore")
    print("Recovered plaintext:")
    print(result)
    return result

if __name__ == "__main__":
    decrypt_ecb_with_random_prefix(encryption_oracle)