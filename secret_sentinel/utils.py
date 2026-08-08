import math


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequency = {}
    for ch in value:
        frequency[ch] = frequency.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in frequency.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_text_bytes(data: bytes) -> bool:
    if not data:
        return True
    if b"\0" in data:
        return False
    text_chars = bytes(range(32, 127)) + b"\n\r\t\b"
    return all(byte in text_chars for byte in data[:1024])
