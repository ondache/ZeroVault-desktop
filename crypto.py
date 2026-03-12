import secrets
import hashlib
import base64

from wordlist import WORDLIST


# https://www.hivesystems.com/blog/are-your-passwords-in-the-green-2023
MODES = {
    'STRONG': {
        'hash-key-size': 16,
        'password-length': 24,
        'iterations': 1_000_000
    },
    'ULTRA': {
        'hash-key-size': 88,
        'password-length': 120,
        'iterations': 5_000_000
    }
}


def generate_mnemonic_12() -> str:
    entropy = secrets.token_bytes(16)
    checksum = hashlib.sha256(entropy).digest()[0] >> 4

    entropy_int = int.from_bytes(entropy, 'big')
    combined = (entropy_int << 4) | checksum

    # split into 12 indexes, each is 11 bits
    indexes = [(combined >> (11 * (11 - i))) & 0x7FF for i in range(12)]
    words = [WORDLIST[i] for i in indexes]
    return ' '.join(words)


def is_seed_valid(seed: int) -> bool:
    if len(seed.to_bytes(17, 'big')) != 17:
        return False
    checksum = seed & 0xF
    entropy_int = seed >> 4
    entropy = entropy_int.to_bytes(16, 'big')
    return checksum == (hashlib.sha256(entropy).digest()[0] >> 4)


def humanize(buffer: bytes) -> str:
    # Using url safe *_ chars instead of base64's +/ chars
    return base64.b64encode(buffer, altchars=b'*_').decode('utf-8').replace('=', '-')


def generate_password(seed: int, passphrase: str, service: str, year: str, quarter: str, mode: str, *, key_size_override: int = None, iterations_override: int = None):
    seed_bytes = seed.to_bytes(17, 'big')
    quarter = quarter if quarter == '' else f'q{quarter}'
    meta = f'{service}{year}{quarter}'
    salt = (passphrase + meta).ljust(16, '*').encode('utf-8')
    key_size = key_size_override or MODES[mode]['hash-key-size']
    iterations = iterations_override or MODES[mode]['iterations']
    derived = derive_key(password=seed_bytes, salt=salt, key_size=key_size, iterations=iterations)
    password = humanize(derived)
    return password

def derive_key(password: bytes, salt: bytes, key_size: int, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name='sha512',
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=key_size,
    )
