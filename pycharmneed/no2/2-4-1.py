import base64
import binascii
from hashlib import sha1
import codecs
from Crypto.Cipher import AES

def set_parity(hex_key: str) -> bytes:
    """
    输入8字节hex字符串，返回带奇偶校验的8字节bytes
    每字节最低位为parity位，使字节中1的个数为偶数
    """
    raw = bytearray(binascii.unhexlify(hex_key))
    for i in range(len(raw)):
        b = raw[i] & 0xFE  # 最高7位
        parity = 1 if bin(b).count('1') % 2 == 0 else 0
        raw[i] = b | parity
    return bytes(raw)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def mrz_to_key(mrz: str) -> bytes:
    """
    根据MRZ信息生成16字节AES密钥（带奇偶校验）
    """
    passport_no = mrz[:10]
    birth_date = mrz[13:20]
    expiry_date = mrz[21:28]
    mrz_data = passport_no + birth_date + expiry_date

    mrz_hash = sha1(mrz_data.encode()).hexdigest()
    kseed = mrz_hash[:32]
    c = '00000001'
    d = kseed + c
    d_bytes = codecs.decode(d, 'hex')
    d_hash = sha1(d_bytes).hexdigest().upper()

    k_a = d_hash[:16]   # 8字节（16字符）
    k_b = d_hash[16:32] # 8字节（16字符）

    key_a = set_parity(k_a)  # bytes, 8字节
    key_b = set_parity(k_b)  # bytes, 8字节
    full_key = key_a + key_b # bytes, 16字节
    return full_key

def main():
    # 可选：加权和校验示例
    a = [7, 3, 1] * 2
    b = [1, 1, 1, 1, 1, 6]
    weighted_sum = sum(a[i] * b[i] for i in range(6)) % 10
    print("加权和校验位:", weighted_sum)

    cipher_b64 = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'
    ciphertext = base64.b64decode(cipher_b64)

    mrz = '12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4'
    aes_key = mrz_to_key(mrz)
    print("解密密钥:", binascii.hexlify(aes_key).decode(), "长度:", len(aes_key))  # 应该是16字节

    iv = binascii.unhexlify('0' * 32)   # 16字节全0
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    print("解密结果（十六进制）:", decrypted.hex())
    try:
        # 去除PKCS7填充
        plaintext = pkcs7_unpad(decrypted)
        print("去除填充后的明文:", plaintext.decode('utf-8', errors='replace'))
    except Exception as e:
        print("去填充失败:", e)
        print("原始解密结果（ASCII）:", decrypted.decode('utf-8', errors='replace'))

if __name__ == "__main__":
    main()