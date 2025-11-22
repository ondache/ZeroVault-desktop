import base64
import os
import time
from getpass import getpass

from crypto import is_seed_valid, get_hash
from wordlist import word_to_index, is_seed_phrase_valid


# https://www.hivesystems.com/blog/are-your-passwords-in-the-green-2023
MODES = [
    {
        'name': 'STRONG',
        'hash-key-size': 21,
        'password-length': 28,
        'iterations': 10_000_000
    },
    {
        'name': 'ULTRA',
        'hash-key-size': 90,
        'password-length': 120,
        'iterations': 100_000_000
    }
]


def mnemonic_to_seed(seed_phrase: str) -> bytes:
    """
    Convert a 12-word BIP-39 seed phrase to its 16-byte entropy +
    1-byte checksum = 17-byte vector.

    :param seed_phrase: 12 words separated by space
    :return: 17 bytes seed
    """
    indices = [word_to_index(w) for w in seed_phrase.split()]
    if len(indices) != 12:
        raise ValueError("Exactly 12 words required")

    # 132-bit concatenation
    bit_str = ''.join(f"{i:011b}" for i in indices)  # 132 bits
    entropy_int = int(bit_str, 2)
    return entropy_int.to_bytes(17, byteorder="big")


def enter_seed_phrase() -> bytes:
    seed_phrase = getpass("Enter seed-phrase: ").lower()
    if seed_phrase.count(" ") != 11:
        print("Incorrect format! 12 words are required!")
        return enter_seed_phrase()
    if not is_seed_phrase_valid(seed_phrase):
        print("Incorrect word(s)!")
        return enter_seed_phrase()
    seed = mnemonic_to_seed(seed_phrase)
    if not is_seed_valid(seed):
        print("Incorrect seed-phrase! Checksum mismatch!")
        return enter_seed_phrase()
    return seed


def enter_passphrase() -> bytes:
    passphrase = getpass("Enter pass-phrase (leave empty for none): ")
    if len(passphrase) != 0 and len(passphrase.strip()) == 0:
        print("Invalid passphrase!")
        return enter_passphrase()
    if len(passphrase) != 0 and getpass("Confirm pass-phrase: ") != passphrase:
        print("Passphrases don't match!")
        return enter_passphrase()
    return passphrase.encode('utf-8')


def enter_meta() -> bytes:
    meta = input('Enter service, year and quarter (like "yahoomail 2025 2"): ')
    if meta.count(" ") != 2:
        print("Incorrect format!")
        return enter_meta()
    service, year, quarter = meta.split()
    if not quarter in {'1', '2', '3', '4'}:
        print("Incorrect quarter!")
        return enter_meta()
    if not year.isdigit() and len(year) != 4:
        print("Incorrect year!")
        return enter_meta()
    if len(service) == 0:
        print("Incorrect service!")
        return enter_meta()
    return f'{service}{year}q{quarter}'.encode('utf-8')


def enter_mode() -> dict:
    message = 'Enter mode (digit):\n' + ''.join((f'{i+1}. {mode['name']} (len {mode['password-length']})\n' for i, mode in enumerate(MODES)))
    mode = input(message)
    if not mode.isdigit() or not 1 <= int(mode) <= len(MODES):
        print("Incorrect mode! Enter just digit!")
        return enter_mode()
    return MODES[int(mode) - 1]


def humanize_hash(hashed: bytes) -> str:
    # Using url safe *_ chars instead of base64's +/ chars
    return base64.b64encode(hashed, altchars=b'*_').decode('utf-8')


def print_password(password: str) -> None:
    print(f"Your password is ({len(password)} letters):\n{password}")
    input("Press enter to exit...")


def main() -> None:
    seed = enter_seed_phrase()
    passphrase = enter_passphrase()
    meta = enter_meta()
    mode = enter_mode()
    print('Generating password...')
    start = time.perf_counter()
    hashed = get_hash(seed, passphrase + meta, mode['hash-key-size'], mode['iterations'])
    print(f'Generation took {time.perf_counter() - start} seconds')
    password = humanize_hash(hashed)
    print_password(password)
    os.system('cls' if os.name == 'nt' else 'clear')


if __name__ == "__main__":
    main()
