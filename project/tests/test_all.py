"""
Sanity tests for the whole project. Run with: pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from padding_oracle.server import CookieService, CheckResult
from padding_oracle import attack as PA
from padding_oracle.aes_core import pkcs7_unpad

from bleichenbacher.rsa_core import RSAKey
from bleichenbacher.attack import attack_rsa_key, AttackStats


def test_padding_oracle_decrypts_multiblock_secret():
    svc = CookieService(vulnerable=True)
    secret = b"user=alice;admin=false;note=a reasonably long secret cookie value"
    iv, ct, _ = svc.issue_cookie(secret)
    oracle = lambda prev, target: svc.padding_oracle(prev, target)
    stats = PA.AttackStats()
    recovered = PA.decrypt(oracle, iv, ct, stats)
    assert pkcs7_unpad(recovered) == secret
    assert stats.queries > 0


def test_padding_oracle_forges_admin_cookie():
    svc = CookieService(vulnerable=True)
    oracle = lambda prev, target: svc.padding_oracle(prev, target)
    stats = PA.AttackStats()
    desired = b"user=mallory;admin=true"
    iv, ct = PA.forge_ciphertext(oracle, desired, stats)
    assert svc.check(iv, ct) == CheckResult.OK
    from padding_oracle.aes_core import cbc_decrypt_and_unpad
    assert cbc_decrypt_and_unpad(svc.key, iv, ct) == desired


def test_encrypt_then_mac_blocks_the_oracle():
    svc = CookieService(vulnerable=False)
    secret = b"user=alice;admin=false;"
    iv, ct, tag = svc.issue_cookie(secret)
    import os as _os
    seen = set()
    for _ in range(200):
        tampered = bytearray(iv)
        tampered[-1] ^= _os.urandom(1)[0]
        seen.add(svc.check(bytes(tampered), ct, tag=None))
    assert seen == {CheckResult.REJECTED}


def test_bleichenbacher_recovers_message_small_key():
    key = RSAKey(bits=128)
    msg = b"hi"
    ct = key.encrypt(msg)
    recovered, stats = attack_rsa_key(key, ct, bits_required=16)
    assert recovered == msg
    assert stats.queries > 0


if __name__ == "__main__":
    test_padding_oracle_decrypts_multiblock_secret()
    print("test_padding_oracle_decrypts_multiblock_secret: PASS")
    test_padding_oracle_forges_admin_cookie()
    print("test_padding_oracle_forges_admin_cookie: PASS")
    test_encrypt_then_mac_blocks_the_oracle()
    print("test_encrypt_then_mac_blocks_the_oracle: PASS")
    test_bleichenbacher_recovers_message_small_key()
    print("test_bleichenbacher_recovers_message_small_key: PASS")
