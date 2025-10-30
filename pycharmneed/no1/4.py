from __future__ import annotations
import hashlib
import itertools
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Optional

TARGET_HASH_HEX = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"
TARGET_DIGEST = bytes.fromhex(TARGET_HASH_HEX)

KEY_CHARS: List[tuple[bytes, bytes]] = [
    (b"Q", b"q"),
    (b"W", b"w"),
    (b"%", b"5"),
    (b"(", b"8"),
    (b"=", b"0"),
    (b"I", b"i"),
    (b"*", b"+"),
    (b"N", b"n"),
]
def check(bitstr: str) -> bool:
    return bitstr[:3].count("0") > 0 and bitstr[3:].count("0") > 0

def build_choice_bytes(bitstr: str) -> List[bytes]:
    return [KEY_CHARS[i][int(b)] for i, b in enumerate(bitstr)]

def try_pattern(bitstr: str) -> Optional[bytes]:
    chosen = build_choice_bytes(bitstr)
    if len(set(chosen)) < len(chosen):
        perms = set(itertools.permutations(chosen, len(chosen)))
    else:
        perms = itertools.permutations(chosen, len(chosen))
    for perm in perms:
        cand = b"".join(perm)
        if hashlib.sha1(cand).digest() == TARGET_DIGEST:
            return cand
    return None

def gen_patterns() -> List[str]:
    return [format(i, "08b") for i in range(256) if check(format(i, "08b"))]


def main() -> None:
    start = time.perf_counter()
    patterns = gen_patterns()
    found_plain: Optional[bytes] = None

    with ProcessPoolExecutor() as exe:
        futures = {exe.submit(try_pattern, p): p for p in patterns}
        try:
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    found_plain = res
                    exe.shutdown(cancel_futures=True)
                    break
        except KeyboardInterrupt:
            try:
                exe.shutdown(cancel_futures=True)
            except Exception:
                pass

    elapsed = time.perf_counter() - start
    if found_plain is not None:
        try:
            print(found_plain.decode("utf-8", errors="replace"))
        except Exception:
            print(found_plain)
    else:
        print("NOT FOUND")


if __name__ == "__main__":
    main()