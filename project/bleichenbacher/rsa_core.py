"""
rsa_core.py
-----------
A small textbook RSA implementation with PKCS#1 v1.5 encryption padding
(RFC 8017 sec. 7.2.1), used as the target of Bleichenbacher's attack.

NOTE ON KEY SIZES: production RSA uses >=2048-bit moduli. We default to
much smaller sizes (e.g. 256-768 bits) so the *full* attack -- including
the expensive "find the first conforming s" step -- finishes in seconds
to minutes on a laptop, which lets us sweep several modulus sizes and
plot how cost grows. The algorithm is identical regardless of size; only
the search space (and hence the query count) changes. This mirrors how
Bleichenbacher-style attacks are normally taught and demonstrated
(e.g. CTF-style ROBOT/ Bleichenbacher exercises) -- see the report for
the real-world incidents (DROWN, ROBOT, Marvin) that used this attack
against full 1024/2048/4096-bit keys.
"""
import math
import os
from sympy import randprime


class RSAKey:
    def __init__(self, bits: int, e: int = 65537, seed: int | None = None):
        self.bits = bits
        self.e = e
        half = bits // 2
        if seed is not None:
            import random
            random.seed(seed)
        p = randprime(2 ** (half - 1), 2 ** half)
        q = randprime(2 ** (half - 1), 2 ** half)
        while q == p:
            q = randprime(2 ** (half - 1), 2 ** half)
        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.d = pow(e, -1, phi)
        self.k = (self.n.bit_length() + 7) // 8  # byte length of n

    # -- raw RSA ----------------------------------------------------------
    def encrypt_int(self, m: int) -> int:
        return pow(m, self.e, self.n)

    def decrypt_int(self, c: int) -> int:
        return pow(c, self.d, self.n)

    # -- PKCS#1 v1.5 encryption padding (RFC 8017 7.2.1) -------------------
    def pkcs1_encode(self, message: bytes) -> bytes:
        k = self.k
        if len(message) > k - 11:
            raise ValueError("message too long for this modulus")
        ps_len = k - len(message) - 3
        ps = bytearray()
        while len(ps) < ps_len:
            b = os.urandom(1)
            if b != b"\x00":
                ps += b
        return b"\x00\x02" + bytes(ps) + b"\x00" + message

    def pkcs1_decode(self, em: bytes) -> bytes:
        """Strict decode: raises ValueError if padding is not
        0x00 0x02 <nonzero bytes> 0x00 <message>."""
        if len(em) != self.k or em[0:1] != b"\x00" or em[1:2] != b"\x02":
            raise ValueError("bad header")
        idx = em.find(b"\x00", 2)
        if idx < 10:  # RFC requires at least 8 bytes of padding string
            raise ValueError("bad padding / message marker")
        return em[idx + 1:]

    def encrypt(self, message: bytes) -> bytes:
        em = self.pkcs1_encode(message)
        m_int = int.from_bytes(em, "big")
        c_int = self.encrypt_int(m_int)
        return c_int.to_bytes(self.k, "big")

    def decrypt(self, ciphertext: bytes) -> bytes:
        c_int = int.from_bytes(ciphertext, "big")
        m_int = self.decrypt_int(c_int)
        em = m_int.to_bytes(self.k, "big")
        return self.pkcs1_decode(em)

    # -- the oracle used by the attack -------------------------------------
    def conforming_oracle(self, c_int: int, bits_required: int = 16) -> bool:
        """True iff the top `bits_required` bits of the decrypted value
        equal the top bits of the pattern 0x00 0x02 (16 bits total).

        bits_required=16 is the real PKCS#1 v1.5 check (the one
        Bleichenbacher's attack uses). Smaller values simulate a *more
        permissive* oracle (fewer header bits enforced -> conforming
        values are easier to find -> step 2a is cheaper), which is the
        "oracle strictness" axis explored in the experiments: it models
        how much the attack's cost depends on how many structural bits
        the server's error behaviour actually leaks (compare Manger's
        attack on OAEP, which leaks only 1 bit and needs a different,
        more efficient search strategy)."""
        assert 1 <= bits_required <= 16
        m_int = self.decrypt_int(c_int)
        total_bits = self.k * 8
        pattern_16 = 0b0000000000000010  # 0x00 0x02
        target_top = pattern_16 >> (16 - bits_required)
        value_top = m_int >> (total_bits - bits_required)
        return value_top == target_top
