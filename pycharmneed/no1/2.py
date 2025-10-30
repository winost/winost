
from __future__ import annotations

import base64
import sys
import time
from typing import List, Optional

# -------------------- 基础操作 --------------------
def repeating_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    k = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % k]
    return bytes(out)

def read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def read_multiline(prompt: str) -> str:
    print(prompt + "（结束输入请空行回车）:")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)

# -------------------- 编码解析 --------------------
def parse_cipher_input(kind: str, text: str) -> bytes:
    kind = kind.lower()
    if kind in ("hex",):
        return bytes.fromhex("".join(text.split()))
    if kind in ("b64", "base64"):
        return base64.b64decode("".join(text.split()))
    raise ValueError("不支持的格式: " + kind)

def parse_key_input(kind: str, text: str) -> bytes:
    kind = kind.lower()
    if kind in ("hex",):
        return bytes.fromhex("".join(text.split()))
    return text.encode("utf-8")

def try_decode_utf8(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except Exception:
        return b.decode("utf-8", errors="replace")

# -------------------- 破解相关（简洁实现） --------------------
EN_FREQ = {
    'a':0.08167,'b':0.01492,'c':0.02782,'d':0.04253,'e':0.12702,'f':0.02228,'g':0.02015,
    'h':0.06094,'i':0.06966,'j':0.00153,'k':0.00772,'l':0.04025,'m':0.02406,'n':0.06749,
    'o':0.07507,'p':0.01929,'q':0.00095,'r':0.05987,'s':0.06327,'t':0.09056,'u':0.02758,
    'v':0.00978,'w':0.02360,'x':0.00150,'y':0.01974,'z':0.00074,' ':0.13000
}

def english_score(text: bytes) -> float:
    sc = 0.0
    bad = 0
    for b in text:
        if b in (9,10,13) or 32 <= b <= 126:
            ch = chr(b).lower()
            sc += EN_FREQ.get(ch, 0)
        else:
            bad += 1
    return sc - bad * 0.5

def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("长度需相等")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))

def normalized_distance(cipher: bytes, keysize: int, blocks: int = 4) -> float:
    if len(cipher) < keysize * 2:
        return float('inf')
    d = []
    max_blocks = min(blocks, len(cipher) // keysize - 1)
    for i in range(max_blocks):
        a = cipher[i*keysize:(i+1)*keysize]
        b = cipher[(i+1)*keysize:(i+2)*keysize]
        d.append(hamming_distance(a, b) / keysize)
    return sum(d) / len(d) if d else float('inf')

def single_byte_key_for_block(block: bytes) -> int:
    best_k = 0
    best_s = float('-inf')
    for k in range(256):
        p = bytes(b ^ k for b in block)
        s = english_score(p)
        if s > best_s:
            best_s = s
            best_k = k
    return best_k

def try_keysize_and_decrypt(cipher: bytes, ks: int) -> tuple[bytes, float, bytes]:
    transposed = [cipher[i::ks] for i in range(ks)]
    key_bytes: List[int] = []
    for block in transposed:
        key_bytes.append(single_byte_key_for_block(block))
    key = bytes(key_bytes)
    plain = repeating_xor(cipher, key)
    return key, english_score(plain), plain

def crack_repeating_xor(cipher: bytes, kmin: int = 2, kmax: int = 40, top_n: int = 5):
    kmax = min(kmax, max(kmin, len(cipher)//2))
    scores = []
    for ks in range(kmin, kmax+1):
        nd = normalized_distance(cipher, ks, blocks=6)
        scores.append((ks, nd))
    scores.sort(key=lambda x: x[1])
    candidates = [ks for ks, _ in scores[:top_n]]
    results = []
    for ks in candidates:
        key, score, plain = try_keysize_and_decrypt(cipher, ks)
        results.append((ks, key, score, plain))
    results.sort(key=lambda x: x[2], reverse=True)
    return results

# -------------------- 交互菜单（直接运行） --------------------
def menu() -> None:
    print("1) 加密 ")
    print("2) 解密 ")
    print("3) 破解 ")
    print("0) 退出")
    choice = input("请选择 (0-3) [3]: ").strip() or "3"
    if choice not in ("0","1","2","3"):
        print("无效选择，退出。"); return
    if choice == "0":
        return
    if choice == "1":
        # 加密
        text = input("输入明文（回车完成）: ")
        keytxt = input("输入密钥（文本）: ")
        outfmt = input("输出格式 hex/b64 [hex]: ").strip() or "hex"
        cipher = repeating_xor(text.encode("utf-8"), keytxt.encode("utf-8"))
        if outfmt.lower() in ("b64","base64"):
            print(base64.b64encode(cipher).decode())
        else:
            print(cipher.hex())
        return
    if choice == "2":
        # 解密
        kind = input("密文格式 hex/b64/file [hex]: ").strip() or "hex"
        if kind.lower() == "file":
            path = input("输入密文文件路径: ").strip()
            try:
                cipher = read_file_bytes(path)
            except Exception as e:
                print("读取文件失败:", e); return
        else:
            txt = read_multiline("粘贴密文")
            try:
                cipher = parse_cipher_input(kind, txt)
            except Exception as e:
                print("解析密文失败:", e); return
        keymode = input("密钥类型 text/hex [text]: ").strip() or "text"
        if keymode.lower() == "hex":
            khex = input("粘贴密钥 hex: ").strip()
            try:
                key = parse_key_input("hex", khex)
            except Exception as e:
                print("解析密钥失败:", e); return
        else:
            ktxt = input("输入密钥文本: ")
            key = parse_key_input("text", ktxt)
        plain = repeating_xor(cipher, key)
        print("\n----- 解密结果 -----")
        print(try_decode_utf8(plain))
        return
    if choice == "3":
        # 破解
        kind = input("密文格式 hex/b64/file [b64]: ").strip() or "b64"
        if kind.lower() == "file":
            path = input("输入密文文件路径: ").strip()
            try:
                cipher = read_file_bytes(path)
            except Exception as e:
                print("读取文件失败:", e); return
        else:
            txt = read_multiline("粘贴密文")
            try:
                cipher = parse_cipher_input(kind, txt)
            except Exception as e:
                print("解析密文失败:", e); return
        if not cipher:
            print("空输入，退出"); return
        try:
            kmin = int(input("最小密钥长度 [2]: ").strip() or "2")
            kmax = int(input("最大密钥长度 [40]: ").strip() or "40")
            cand = int(input("尝试前多少个长度候选 [5]: ").strip() or "5")
        except Exception:
            print("参数错误，使用默认 2..40, top 5")
            kmin, kmax, cand = 2, 40, 5
        start = time.perf_counter()
        results = crack_repeating_xor(cipher, kmin, kmax, cand)
        elapsed = time.perf_counter() - start
        if results:
            best = results[0]
            key = best[1]
            plain = best[3]
            print("\n----- 最可能的密钥 -----")
            try:
                print(key.decode("utf-8"))
            except Exception:
                print(key.hex())
            print("\n----- 对应明文（尝试 UTF-8 解码） -----")
            print(try_decode_utf8(plain))
            print(f"\nTime: {elapsed:.2f}s")
        else:
            print("未找到候选。")
        return

def main() -> None:
    try:
        menu()
    except KeyboardInterrupt:
        print("\n已取消。"); sys.exit(1)

if __name__ == "__main__":
    main()