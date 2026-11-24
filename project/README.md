# Oracles Everywhere: CBC Padding Oracle + Bleichenbacher's Attack on RSA PKCS#1 v1.5

Course project for Cryptography (2026/2), UFMG.

Implements, measures, and defends against two classic decryption-oracle
attacks:

1. **Vaudenay's padding-oracle attack** on AES-CBC (`padding_oracle/`)
2. **Bleichenbacher's adaptive chosen-ciphertext attack** on RSA PKCS#1 v1.5
   (`bleichenbacher/`)

## Layout

```
padding_oracle/
  aes_core.py       AES-CBC + PKCS#7 padding, HMAC helpers (Encrypt-then-MAC)
  server.py         CookieService: vulnerable and defended modes; Flask wrapper
  attack.py         Vaudenay decryption attack + ciphertext-forging extension
bleichenbacher/
  rsa_core.py       Textbook RSA keygen + PKCS#1 v1.5 encode/decode + oracle
  attack.py         Full Bleichenbacher algorithm (steps 1-4)
experiments/
  exp_padding_oracle_cost.py    queries vs. plaintext length
  exp_bb_modulus_size.py        queries & time vs. RSA modulus size
  exp_bb_noisy_oracle.py        success rate vs. oracle error probability
  make_plots.py                 renders the 3 figures in figures/
tests/
  test_all.py        pytest-style sanity tests for every attack and defense
figures/              generated CSVs + PNG plots (see report)
demo_http.py          single-process live demo over real HTTP (Flask + requests)
server_demo.py         TERMINAL 1: the vulnerable server as its own process
attacker_demo.py       TERMINAL 2: the attacker, live byte-by-byte progress display
```

## Quick start

```bash
pip install cryptography flask requests sympy matplotlib

# unit tests
python3 tests/test_all.py

# live HTTP demo, single process (starts a real Flask server, attacks it over the network)
python3 demo_http.py

# live HTTP demo, two separate processes (recommended for presenting):
#   terminal 1:
python3 server_demo.py
#   terminal 2, once terminal 1 says "Running on http://127.0.0.1:5055":
python3 attacker_demo.py
# attacker_demo.py prints only HTTP requests/responses and shows the
# recovered plaintext filling in live, byte by byte, with a running
# query counter -- it never imports server.py or touches the key.
# Compare the key server_demo.py prints at startup with everything
# attacker_demo.py prints: the key never appears there.

# run all experiments and regenerate the plots
python3 experiments/exp_padding_oracle_cost.py
python3 experiments/exp_bb_modulus_size.py
python3 experiments/exp_bb_noisy_oracle.py
python3 experiments/make_plots.py
```

## Notes on scale

RSA moduli in the Bleichenbacher experiments are 128-384 bits, not the
2048+ bits used in production, purely so the *full* attack (including the
expensive random search in step 2a) finishes in seconds rather than hours
on a laptop. The algorithm is unchanged; only the search space shrinks.
See the report for why query count is largely independent of modulus size
in the first place.

## Real-world context

- Padding oracle: ASP.NET (2010), POODLE, Lucky Thirteen.
- Bleichenbacher-style oracles: DROWN (2016), ROBOT (2017), Marvin (2023).
- The eMudhra incident (October 2026) is a reminder that key-generation
  and validation failures keep recurring, even if that particular case
  involved undersized ECC keys rather than RSA.
