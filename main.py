import base64
import os
import time
from getpass import getpass

from crypto import is_seed_valid, derive_key
from wordlist import word_to_index, is_seed_phrase_valid


# https://www.hivesystems.com/blog/are-your-passwords-in-the-green-2023
MODES = [
    {
        'name': 'STRONG',
        'hash-key-size': 16,
        'password-length': 24,
        'iterations': 1_000_000
    },
    {
        'name': 'ULTRA',
        'hash-key-size': 88,
        'password-length': 120,
        'iterations': 5_000_000
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


def enter_passphrase() -> str:
    passphrase = getpass("Enter pass-phrase (leave empty for none): ").strip()
    if len(passphrase) != 0 and len(passphrase.strip()) == 0:
        print("Invalid passphrase!")
        return enter_passphrase()
    if len(passphrase) != 0 and getpass("Confirm pass-phrase: ").strip() != passphrase:
        print("Passphrases don't match!")
        return enter_passphrase()
    return passphrase


def enter_meta() -> str:
    meta = input('Enter service, year and quarter (like "yahoomail 2025 2"): ')
    metas = iter(meta.strip().split())
    service, year, quarter = next(metas, ''), next(metas, ''), next(metas, '')
    if next(metas, None) is not None:
        print('Too many arguments!')
        return enter_meta()
    if not quarter in {'1', '2', '3', '4', ''}:
        print("Incorrect quarter!")
        return enter_meta()
    if quarter != '':
        quarter = f'q{quarter}'
    if year != '' and (not year.isdigit() or len(year) != 4):
        print("Incorrect year!")
        return enter_meta()
    return f'{service}{year}{quarter}'


def enter_mode() -> dict:
    message = 'Enter mode (digit):\n' + ''.join((f'{i+1}. {mode['name']} (len {mode['password-length']})\n' for i, mode in enumerate(MODES)))
    mode = input(message)
    if not mode.isdigit() or not 1 <= int(mode) <= len(MODES):
        print("Incorrect mode! Enter just digit!")
        return enter_mode()
    return MODES[int(mode) - 1]


def humanize(buffer: bytes) -> str:
    # Using url safe *_ chars instead of base64's +/ chars
    return base64.b64encode(buffer, altchars=b'*_').decode('utf-8').replace('=', '-')


def print_password(password: str) -> None:
    print(f"Your password is ({len(password)} letters):\n{password}")
    input("Press enter to exit...")


def greet() -> None:
    print("Password Generator v2")


def main() -> None:
    greet()
    seed = enter_seed_phrase()
    passphrase = enter_passphrase()
    meta = enter_meta()
    mode = enter_mode()
    print('Generating password...')
    start = time.perf_counter()
    salt = (passphrase + meta).ljust(16, '*').encode('utf-8')
    derived = derive_key(seed, salt, mode['hash-key-size'], mode['iterations'])
    print(f'Generation took {time.perf_counter() - start:.2f} seconds')
    password = humanize(derived)
    print_password(password)
    os.system('cls' if os.name == 'nt' else 'clear')


if __name__ == "__main__":
    main()
