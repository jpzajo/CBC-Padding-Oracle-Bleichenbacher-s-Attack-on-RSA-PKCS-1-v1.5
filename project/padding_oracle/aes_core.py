"""
aes_core.py
-----------
Thin wrappers around AES-CBC and PKCS#7 padding, used to build the
vulnerable ("padding leaks") and defended ("encrypt-then-MAC") services
in server.py.

We rely on the `cryptography` library for the AES block cipher itself --
the point of the project is the *protocol-level* flaw (what the server
reveals about padding validity), not reinventing AES.
"""
import hmac
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding

BLOCK_SIZE = 16  # AES block size in bytes


class PaddingError(Exception):
    """Raised when PKCS#7 unpadding fails (bad padding bytes)."""
    pass


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """PKCS#7-pad `plaintext` and encrypt it under AES-CBC(key, iv)."""
    padder = crypto_padding.PKCS7(BLOCK_SIZE * 8).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def cbc_decrypt_raw(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-CBC(key, iv, ciphertext) and return the *padded*
    plaintext, WITHOUT checking or removing padding. Raises PaddingError
    if the plaintext length / IV usage would be malformed (should not
    normally happen -- real failures come from pkcs7_unpad)."""
    if len(ciphertext) % BLOCK_SIZE != 0 or len(ciphertext) == 0:
        raise PaddingError("ciphertext is not a nonzero multiple of the block size")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def pkcs7_unpad(padded: bytes) -> bytes:
    """Remove PKCS#7 padding; raises PaddingError on malformed padding."""
    try:
        unpadder = crypto_padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception as exc:  # cryptography raises ValueError internally
        raise PaddingError(str(exc)) from exc


def cbc_decrypt_and_unpad(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Full decrypt: AES-CBC decrypt then PKCS#7-unpad. Raises PaddingError
    if padding is invalid."""
    padded = cbc_decrypt_raw(key, iv, ciphertext)
    return pkcs7_unpad(padded)


# ---------------------------------------------------------------------------
# Encrypt-then-MAC building blocks, used by the *defended* service.
# ---------------------------------------------------------------------------

def hmac_tag(mac_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """HMAC-SHA256 over (iv || ciphertext)."""
    return hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()


def hmac_verify(mac_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bool:
    expected = hmac_tag(mac_key, iv, ciphertext)
    return hmac.compare_digest(expected, tag)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
