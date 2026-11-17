# Secure File Tool

A small Python command-line tool that encrypts and decrypts files with a password and checks whether a file has been changed.

## Features

- Encrypts files with AES-256-GCM (authenticated encryption)
- Derives the key from a password using PBKDF2-HMAC-SHA256 with a random salt and 600,000 iterations
- Uses a fresh random nonce for every encryption
- Shows and compares SHA-256 hashes to detect changed files
- Rejects wrong passwords and files that were modified after encryption

## How to Run

```
python -m pip install cryptography
python securefile.py
```

Then choose an option from the menu:

1. Show the SHA-256 hash of a file
2. Encrypt a file (creates `filename.enc`)
3. Decrypt a file
4. Check a file against an expected hash

## What I Tested

- Wrong password: decryption fails
- Modified file: the hash check reports a mismatch
- Corrupted encrypted file: decryption fails even with the correct password

## Concepts Used

AES, authenticated encryption (GCM), key derivation, salts and nonces, SHA-256 hashing, confidentiality and integrity.

## Notes

A learning project built alongside my Network Security coursework. It is not audited software, so don't use it to protect important data.
