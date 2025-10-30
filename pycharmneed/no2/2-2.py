class PaddingError(Exception):
    pass

def pkcs7_remove_padding(data: bytes) -> bytes:
    if not data:
        raise PaddingError("数据不能为空")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise PaddingError(f"填充长度无效: {pad_len}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise PaddingError("填充字节不一致")
    return data[:-pad_len]

if __name__ == "__main__":

    valid_padded = b"ICE ICE BABY\x04\x04\x04\x04"

    invalid_padded1 = b"ICE ICE BABY\x05\x05\x05\x05"

    invalid_padded2 = b"ICE ICE BABY\x01\x02\x03\x04"

    test_cases = [
        ("有效填充", valid_padded),
        ("无效填充1", invalid_padded1),
        ("无效填充2", invalid_padded2),
    ]

    for name, case in test_cases:
        try:
            result = pkcs7_remove_padding(case)
            print(f"{name}: 去除填充后为 {result}")
        except PaddingError as err:
            print(f"{name}: 填充错误 {err}")