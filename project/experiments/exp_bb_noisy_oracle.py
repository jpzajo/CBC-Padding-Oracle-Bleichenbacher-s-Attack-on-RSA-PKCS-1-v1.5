"""
Experiment: how does a NOISY oracle affect the Bleichenbacher attack?

A real decryption oracle built from a side channel (e.g. a timing
difference, as in Lucky Thirteen) is not perfectly reliable -- it
occasionally reports the wrong answer. We wrap the exact oracle in a
RandomNoiseOracle that flips its answer with probability p_error, and
measure:
  - the fraction of attack attempts that succeed within a fixed query
    budget (an inconsistent answer can collapse the candidate interval
    set to empty, which we treat as a failure -- see AttackFailed);
  - the mean number of queries used by the attempts that DO succeed.

This models why real attacks (DROWN, ROBOT) need many repeated queries
and statistical techniques to denoise a borderline side channel, and
why a clean, deterministic oracle (p_error = 0) is the "best case" for
the attacker.
"""
import csv
import os
import sys
import random
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bleichenbacher.rsa_core import RSAKey
from bleichenbacher.attack import bleichenbacher_attack, AttackStats, AttackFailed

TRIALS = 8
NOISE_LEVELS = [0.0, 0.0002, 0.0005, 0.001, 0.002]
MODULUS_BITS = 128
MESSAGE = b"hi"
MAX_ITERATIONS = 4000  # bail out quickly on a stuck/noisy run


def make_noisy_oracle(exact_oracle, p_error, rng):
    def noisy(c_int):
        answer = exact_oracle(c_int)
        if rng.random() < p_error:
            answer = not answer
        return answer
    return noisy


rows = []
for p_error in NOISE_LEVELS:
    successes = 0
    query_counts_on_success = []
    rng = random.Random(1234)
    for trial in range(TRIALS):
        key = RSAKey(bits=MODULUS_BITS)
        ct = key.encrypt(MESSAGE)
        c0 = int.from_bytes(ct, "big")
        exact_oracle = lambda c: key.conforming_oracle(c, bits_required=16)
        noisy_oracle = make_noisy_oracle(exact_oracle, p_error, rng)
        stats = AttackStats()
        try:
            m, stats = bleichenbacher_attack(key.n, key.e, key.k, noisy_oracle, c0,
                                              stats=stats, max_iterations=MAX_ITERATIONS)
            em = m.to_bytes(key.k, "big")
            ok = em[2:].rstrip(b"\x00") if False else None  # placeholder, real check below
            recovered_ok = (m.to_bytes(key.k, "big")[-len(MESSAGE):] == MESSAGE)
            if recovered_ok:
                successes += 1
                query_counts_on_success.append(stats.queries)
        except (AttackFailed, RuntimeError):
            pass  # counted as a failure

    success_rate = successes / TRIALS
    mean_q = statistics.mean(query_counts_on_success) if query_counts_on_success else float("nan")
    rows.append((p_error, success_rate, mean_q, len(query_counts_on_success)))
    print(f"p_error={p_error:.4f}  success_rate={success_rate:.2f}  "
          f"mean_queries_on_success={mean_q:.0f}  (n_success={len(query_counts_on_success)}/{TRIALS})")

out_path = os.path.join(os.path.dirname(__file__), "..", "figures", "bb_noisy_oracle.csv")
with open(out_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["p_error", "success_rate", "mean_queries_on_success", "n_success"])
    w.writerows(rows)
print("wrote", out_path)
