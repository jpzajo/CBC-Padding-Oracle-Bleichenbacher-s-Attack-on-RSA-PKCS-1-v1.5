"""
server_demo.py
---------------
TERMINAL 1. Run this first:

    python3 server_demo.py

Starts the vulnerable cookie service as a REAL Flask HTTP server, with
normal request logging left on, so every request the attacker sends
shows up here as a genuine, independent network request -- this process
has no idea an attack is even happening, it just answers /login and
/check calls like any web server would.

The secret key is printed once at startup ONLY so you can show your
audience, by comparing the two terminals, that it never appears in
anything the attacker process prints, sends, or receives.
"""
from padding_oracle.server import CookieService, build_flask_app

HOST, PORT = "127.0.0.1", 5055


def main():
    service = CookieService(vulnerable=True)
    print("=" * 70)
    print(" VULNERABLE COOKIE SERVICE")
    print("=" * 70)
    print(f" listening on: http://{HOST}:{PORT}")
    print(f" secret AES key (for YOUR eyes only): {service.key.hex()}")
    print(" ^ watch terminal 2: this value never appears there.")
    print("=" * 70)
    print()
    app = build_flask_app(service)
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
