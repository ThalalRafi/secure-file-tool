
import getpass
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
ITERATIONS = 600_000


def clean_path(text):
    """Remove spaces and quote marks around a typed file name."""
    return text.strip().strip('"').strip("'")


def sha256_of_file(path):
    """Return the SHA-256 fingerprint of a file as hex text."""
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def derive_key(password, salt):
    """Turn a password into a 256-bit AES key (PBKDF2 with SHA-256)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt_file(path):
    password = getpass.getpass("Choose a password (it stays hidden while you type): ")
    again = getpass.getpass("Type the password again: ")
    if password != again:
        print("The passwords do not match. Nothing was encrypted.")
        return

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    with open(path, "rb") as file:
        data = file.read()

    # AES-GCM encrypts the data and adds a tag that detects any change
    ciphertext = AESGCM(key).encrypt(nonce, data, None)

    output_path = path + ".enc"
    with open(output_path, "wb") as file:
        file.write(salt + nonce + ciphertext)

    print("Encrypted file saved as:", output_path)


def decrypt_file(path):
    password = getpass.getpass("Enter the password: ")

    with open(path, "rb") as file:
        blob = file.read()

    if len(blob) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        print("This file is too short to be one of my encrypted files.")
        return

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]
    key = derive_key(password, salt)

    try:
        data = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        print("Decryption failed: wrong password, or the file was changed.")
        return

    base = path[:-4] if path.endswith(".enc") else path
    name, extension = os.path.splitext(base)
    output_path = name + "_decrypted" + extension
    with open(output_path, "wb") as file:
        file.write(data)

    print("Decrypted file saved as:", output_path)


def compare_hash(path):
    actual = sha256_of_file(path)
    expected = input("Paste the expected SHA-256 hash: ").strip().lower()
    if actual == expected:
        print("MATCH: the file has not been changed.")
    else:
        print("MISMATCH: the file is different from the original!")
        print("Actual hash:", actual)


def main():
    print("=== Secure File Tool ===")
    while True:
        print()
        print("1) Show SHA-256 hash of a file")
        print("2) Encrypt a file with a password (AES-256-GCM)")
        print("3) Decrypt a file")
        print("4) Check a file against an expected hash")
        print("5) Quit")
        choice = input("Choose 1-5: ").strip()

        if choice == "5":
            print("Goodbye.")
            break
        if choice not in ("1", "2", "3", "4"):
            print("Please type a number from 1 to 5.")
            continue

        path = clean_path(input("File name: "))
        if not os.path.isfile(path):
            print("File not found. Check the name and the folder.")
            continue

        if choice == "1":
            print("SHA-256:", sha256_of_file(path))
        elif choice == "2":
            encrypt_file(path)
        elif choice == "3":
            decrypt_file(path)
        elif choice == "4":
            compare_hash(path)


if __name__ == "__main__":
    main()