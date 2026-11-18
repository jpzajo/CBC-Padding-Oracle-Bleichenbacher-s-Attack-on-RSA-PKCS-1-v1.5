"""
attack.py
---------
Vaudenay's (2002) CBC padding-oracle attack.

Notation: for a ciphertext block pair (C_prev, C_target),
    P_target = D_K(C_target) XOR C_prev
The attacker never learns D_K directly, but can choose C_prev freely and
ask the oracle "does D_K(C_target) XOR C_prev end in valid PKCS#7
padding?". By scanning the last byte of a forged C_prev, the attacker
finds a value that makes the padding valid, which (generically) means
the last byte of D_K(C_target) XOR C_prev' is 0x01. Knowing C_prev'[-1]
then gives I[-1] = D_K(C_target)[-1] = C_prev'[-1] XOR 0x01, and hence
P_target[-1] = I[-1] XOR C_prev[-1]. Repeating for padding bytes
0x02 0x02, 0x03 0x03 0x03, ... recovers the whole block.

This module decrypts arbitrary ciphertexts given only such an oracle,
and also implements the companion "encryption" trick: using the oracle
to forge a ciphertext that decrypts to a plaintext of the attacker's
choice.
"""
from dataclasses import dataclass, field

from .aes_core import BLOCK_SIZE


@dataclass
class AttackStats:
    queries: int = 0


def _find_intermediate_byte(oracle, prev_block: bytearray, target_block: bytes,
                             pos: int, pad_val: int, stats: AttackStats) -> int:
    """Find I[pos] = D_K(target_block)[pos] by scanning prev_block[pos]
    so that the padding ends in `pad_val` repeated (BLOCK_SIZE - pos) times.
    `prev_block` already has bytes > pos set to force that padding value."""
    original_byte = prev_block[pos]
    for guess in range(256):
        prev_block[pos] = guess
        stats.queries += 1
        if oracle(bytes(prev_block), target_block):
            # Edge case at pos == BLOCK_SIZE-1: a "valid" 0x01 padding can
            # also arise spuriously if the real last two bytes already
            # looked like 0x02 0x02 before we touched byte 14. Disambiguate
            # by flipping the second-to-last byte and re-checking.
            if pad_val == 1 and pos == BLOCK_SIZE - 2:
                prev_block[pos - 1] ^= 0xFF
                stats.queries += 1
                still_valid = oracle(bytes(prev_block), target_block)
                prev_block[pos - 1] ^= 0xFF
                if not still_valid:
                    continue  # was a false positive; keep scanning
            intermediate_byte = guess ^ pad_val
            prev_block[pos] = original_byte
            return intermediate_byte
    raise RuntimeError("oracle never returned a valid padding — is it really a padding oracle?")


def decrypt_block(oracle, prev_block: bytes, target_block: bytes,
                   stats: AttackStats | None = None) -> bytes:
    """Decrypt one ciphertext block given the oracle and the preceding
    ciphertext block (or the IV, for the first block)."""
    stats = stats or AttackStats()
    intermediate = [0] * BLOCK_SIZE
    forged = bytearray(BLOCK_SIZE)

    for pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - pos
        # Set bytes after `pos` so that, combined with the correct guess at
        # `pos`, they realize the padding pad_val, pad_val, ..., pad_val.
        for j in range(pos + 1, BLOCK_SIZE):
            forged[j] = intermediate[j] ^ pad_val
        intermediate[pos] = _find_intermediate_byte(oracle, forged, target_block, pos, pad_val, stats)

    plaintext = bytes(intermediate[i] ^ prev_block[i] for i in range(BLOCK_SIZE))
    return plaintext


def decrypt(oracle, iv: bytes, ciphertext: bytes,
            stats: AttackStats | None = None) -> bytes:
    """Decrypt a full multi-block ciphertext (IV + C_1 || C_2 || ... || C_n),
    returning the plaintext WITH PKCS#7 padding still attached (strip it
    with aes_core.pkcs7_unpad if you want the unpadded message)."""
    stats = stats or AttackStats()
    blocks = [iv] + [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext = b""
    for i in range(1, len(blocks)):
        plaintext += decrypt_block(oracle, blocks[i - 1], blocks[i], stats)
    return plaintext


def forge_ciphertext(oracle, desired_plaintext: bytes,
                      stats: AttackStats | None = None) -> tuple[bytes, bytes]:
    """
    The "chosen-plaintext via decryption oracle" trick: build a ciphertext
    that decrypts (under the same server/key) to exactly `desired_plaintext`
    (PKCS#7-padded to a multiple of BLOCK_SIZE), WITHOUT ever learning the key.

    Idea: pick an arbitrary final block C_last (e.g. all zero bytes). Treat
    it as "target_block" and recover I = D_K(C_last) using decrypt_block with
    prev_block = zero (the "prev" value is irrelevant to the intermediate
    state; it only affects the XOR at the very end, which we don't use here).
    Then the previous ciphertext block C_prev := I XOR desired_last_block
    makes D_K(C_last) XOR C_prev == desired_last_block, i.e. decrypting
    [..., C_prev, C_last] yields desired_last_block as the last plaintext
    block. Chain this backwards, one block at a time, using a fresh random
    "target" for each new block and an arbitrary IV in front.
    """
    import os
    stats = stats or AttackStats()

    padded = desired_plaintext
    pad_len = BLOCK_SIZE - (len(padded) % BLOCK_SIZE)
    padded += bytes([pad_len]) * pad_len
    plain_blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]

    # Work backwards: blocks_ct[-1] is arbitrary; each earlier block is
    # derived so that decrypting it with the one after it yields the
    # desired plaintext block.
    blocks_ct = [os.urandom(BLOCK_SIZE)]  # last ciphertext block, arbitrary
    for plain_block in reversed(plain_blocks):
        target = blocks_ct[0]
        zero_prev = bytes(BLOCK_SIZE)
        intermediate_bytes = decrypt_block(oracle, zero_prev, target, stats)
        intermediate = bytes(a ^ b for a, b in zip(intermediate_bytes, zero_prev))
        # decrypt_block already XORs with prev_block internally to return
        # plaintext = I XOR prev; since prev was all-zero, that call in
        # fact returned I directly. Keep the explicit XOR above for clarity.
        new_prev = bytes(i ^ p for i, p in zip(intermediate, plain_block))
        blocks_ct.insert(0, new_prev)

    iv = blocks_ct[0]
    ciphertext = b"".join(blocks_ct[1:])
    return iv, ciphertext
