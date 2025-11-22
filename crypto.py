import secrets
import hashlib

from wordlist import WORDLIST


def generate_mnemonic_12() -> str:
    entropy = secrets.token_bytes(16)
    checksum = hashlib.sha256(entropy).digest()[0] >> 4

    entropy_int = int.from_bytes(entropy, 'big')
    combined = (entropy_int << 4) | checksum

    # split into 12 indexes, each is 11 bits
    indexes = [(combined >> (11 * (11 - i))) & 0x7FF for i in range(12)]
    words = [WORDLIST[i] for i in indexes]
    return ' '.join(words)


def is_seed_valid(seed: bytes) -> bool:
    if len(seed) != 17:
        return False
    seed_int = int.from_bytes(seed, 'big')
    checksum = seed_int & 0xF
    entropy_int = seed_int >> 4
    entropy = entropy_int.to_bytes(16, 'big')
    return checksum == (hashlib.sha256(entropy).digest()[0] >> 4)


def derive_key(password: bytes, salt: bytes, key_size: int, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name='sha512',
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=key_size,
    )
