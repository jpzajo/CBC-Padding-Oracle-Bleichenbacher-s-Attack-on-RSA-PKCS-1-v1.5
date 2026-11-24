"""
server.py
---------
Simulates the server side of a session-cookie scheme in two modes:

  * VULNERABLE: AES-CBC-Encrypt-then-MAC-nothing. The /check endpoint
    distinguishes "bad padding" from "bad plaintext otherwise", which is
    exactly the oracle Vaudenay's attack needs.

  * DEFENDED: Encrypt-then-MAC (HMAC-SHA256 over iv||ciphertext). The MAC
    is verified BEFORE any decryption is attempted, so an attacker who
    doesn't know the MAC key can never reach the padding check at all --
    every forged ciphertext is rejected with one generic error.

`CookieService` is the in-process oracle used by the attack and by the
experiments (fast, no network). `build_flask_app` wraps the same logic
in a tiny Flask app so the attack can also be demonstrated end-to-end
over real HTTP, matching the "small HTTP service" described in the
proposal.
"""
from dataclasses import dataclass
from enum import Enum

from . import aes_core as C


class CheckResult(Enum):
    OK = "ok"                    # padding valid (and, in defended mode, MAC valid)
    BAD_PADDING = "bad_padding"  # vulnerable mode only: padding was invalid
    REJECTED = "rejected"        # defended mode: single generic error for everything


class CookieService:
    """An in-process stand-in for the server. Holds secret keys; exposes
    only what a real network service would expose."""

    def __init__(self, vulnerable: bool, seed_key: bytes | None = None, mac_key: bytes | None = None):
        self.vulnerable = vulnerable
        self.key = seed_key or C.random_bytes(16)
        self.mac_key = mac_key or C.random_bytes(32)
        self.query_count = 0  # instrumentation for the experiments

    # -- "login": issue a cookie for a given plaintext -------------------
    def issue_cookie(self, plaintext: bytes) -> tuple[bytes, bytes, bytes | None]:
        iv = C.random_bytes(C.BLOCK_SIZE)
        ct = C.cbc_encrypt(self.key, iv, plaintext)
        if self.vulnerable:
            return iv, ct, None
        tag = C.hmac_tag(self.mac_key, iv, ct)
        return iv, ct, tag

    # -- "check": the oracle the attacker gets to query -------------------
    def check(self, iv: bytes, ciphertext: bytes, tag: bytes | None = None) -> CheckResult:
        self.query_count += 1
        if not self.vulnerable:
            # Encrypt-then-MAC: verify the MAC BEFORE touching the cipher.
            if tag is None or not C.hmac_verify(self.mac_key, iv, ciphertext, tag):
                return CheckResult.REJECTED
            # MAC only verifies ciphertexts WE issued, so padding here is
            # always valid; we still unpad to mirror what a real server does.
            try:
                C.cbc_decrypt_and_unpad(self.key, iv, ciphertext)
                return CheckResult.OK
            except C.PaddingError:
                return CheckResult.REJECTED  # unreachable in practice

        # Vulnerable mode: no MAC at all, decrypt and report padding validity.
        try:
            C.cbc_decrypt_and_unpad(self.key, iv, ciphertext)
            return CheckResult.OK
        except C.PaddingError:
            return CheckResult.BAD_PADDING

    def padding_oracle(self, iv: bytes, ciphertext: bytes) -> bool:
        """Convenience used by the attack: True iff padding was valid.
        Only meaningful (and only available) against the vulnerable service."""
        assert self.vulnerable, "padding_oracle() is only exposed by the vulnerable service"
        return self.check(iv, ciphertext) == CheckResult.OK


def build_flask_app(service: CookieService):
    """Wrap a CookieService in a minimal Flask app, for the live HTTP demo."""
    from flask import Flask, request, jsonify

    app = Flask(__name__)

    @app.post("/login")
    def login():
        username = request.json.get("username", "guest")
        plaintext = f"user={username};admin=false".encode()
        iv, ct, tag = service.issue_cookie(plaintext)
        resp = {"iv": iv.hex(), "ciphertext": ct.hex()}
        if tag is not None:
            resp["tag"] = tag.hex()
        return jsonify(resp)

    @app.post("/check")
    def check():
        data = request.json
        iv = bytes.fromhex(data["iv"])
        ct = bytes.fromhex(data["ciphertext"])
        tag = bytes.fromhex(data["tag"]) if "tag" in data else None
        result = service.check(iv, ct, tag)
        return jsonify({"status": result.value})

    return app
