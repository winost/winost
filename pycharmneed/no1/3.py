from __future__ import annotations

import base64
import sys
import time
from typing import Tuple, List
EN_FREQ = {
    'a':0.08167,'b':0.01492,'c':0.02782,'d':0.04253,'e':0.12702,'f':0.02228,'g':0.02015,
    'h':0.06094,'i':0.06966,'j':0.00153,'k':0.00772,'l':0.04025,'m':0.02406,'n':0.06749,
    'o':0.07507,'p':0.01929,'q':0.00095,'r':0.05987,'s':0.06327,'t':0.09056,'u':0.02758,
    'v':0.00978,'w':0.02360,'x':0.00150,'y':0.01974,'z':0.00074,' ':0.13000
}

def hamming_distance(b1: bytes, b2: bytes) -> int:
    if len(b1) != len(b2):
        raise ValueError("Inputs must have same length")
    return sum((x ^ y).bit_count() for x, y in zip(b1, b2))

def english_score(text: bytes) -> float:
    score = 0.0
    nonprint = 0
    for b in text:
        if b in (9,10,13) or 32 <= b <= 126:
            score += EN_FREQ.get(chr(b).lower(), 0)
        else:
            nonprint += 1
    score -= nonprint * 0.5
    return score

def single_byte_xor_best(block: bytes) -> Tuple[int, float, bytes]:
    best_k = 0
    best_score = float('-inf')
    best_plain = b""
    for k in range(256):
        plain = bytes(b ^ k for b in block)
        s = english_score(plain)
        if s > best_score:
            best_score = s
            best_k = k
            best_plain = plain
    return best_k, best_score, best_plain

def normalized_distance_for_keysize(cipher: bytes, keysize: int, blocks: int = 4) -> float:
    if len(cipher) < keysize * 2:
        return float('inf')
    distances = []
    max_blocks = min(blocks, len(cipher) // keysize - 1)
    for i in range(max_blocks):
        a = cipher[i*keysize:(i+1)*keysize]
        b = cipher[(i+1)*keysize:(i+2)*keysize]
        distances.append(hamming_distance(a, b) / keysize)
    return sum(distances) / len(distances) if distances else float('inf')

def break_for_keysize(cipher: bytes, keysize: int) -> Tuple[bytes, float, bytes]:
    transposed = [cipher[i::keysize] for i in range(keysize)]
    key_bytes: List[int] = []
    for block in transposed:
        k, s, _ = single_byte_xor_best(block)
        key_bytes.append(k)
    key = bytes(key_bytes)
    plain = bytes(c ^ key[i % len(key)] for i, c in enumerate(cipher))
    total_score = english_score(plain)
    return key, total_score, plain

def find_key_and_plain(cipher: bytes, kmin: int = 2, kmax: int = 40, top_n: int = 3):
    candidates = []
    upper = min(kmax, max(kmin, len(cipher)//2))
    for ks in range(kmin, upper + 1):
        nd = normalized_distance_for_keysize(cipher, ks, blocks=4)
        candidates.append((ks, nd))
    candidates.sort(key=lambda x: x[1])
    keys_to_try = [ks for ks, _ in candidates[:top_n]]
    results = []
    for ks in keys_to_try:
        key, score, plain = break_for_keysize(cipher, ks)
        results.append((ks, key, score, plain))
    results.sort(key=lambda x: x[2], reverse=True)
    return results

# ---- HARDCODED BASE64 CIPHERTEXT (from user) ----
HARDCODED_B64 = """
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
"""

def printable_key(k: bytes) -> str:
    try:
        return k.decode('utf-8')
    except Exception:
        return k.hex()

def _self_check():
    a = b"this is a test"
    b = b"wokka wokka!!!"
    if hamming_distance(a, b) != 37:
        raise AssertionError("Hamming check failed")

def main():
    _self_check()
    # decode embedded base64 (remove whitespace/newlines)
    b64clean = "".join(HARDCODED_B64.split())
    try:
        cipher = base64.b64decode(b64clean)
    except Exception as e:
        print("Failed to decode embedded base64:", e, file=sys.stderr)
        return

    start = time.perf_counter()
    results = find_key_and_plain(cipher, kmin=2, kmax=40, top_n=3)
    elapsed = time.perf_counter() - start

    if not results:
        print("No candidates found.")
        return

    best_ks, best_key, best_score, best_plain = results[0]
    print("Key:")
    print(printable_key(best_key))
    print("\nPlaintext (first 4000 chars shown):")
    try:
        print(best_plain.decode('utf-8'))
    except Exception:
        print(best_plain.decode('utf-8', errors='replace'))
    print(f"\nTried top keysize candidates: {[r[0] for r in results]}")
    print(f"Elapsed: {elapsed:.4f}s")

if __name__ == "__main__":
    main()