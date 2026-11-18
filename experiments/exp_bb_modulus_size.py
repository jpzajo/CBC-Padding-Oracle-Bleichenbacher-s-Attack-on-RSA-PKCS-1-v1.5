"""
Experiment: Bleichenbacher attack cost (oracle queries and wall-clock
time) as a function of the RSA modulus size, with the oracle strictness
fixed at the real PKCS#1 v1.5 check (bits_required=16).

Hypothesis (see report): the dominant cost, step 2a's random search for
a conforming multiplier, has expected cost ~ 2^16 independent of the
modulus size, so QUERY COUNT should stay roughly flat (just noisy
around the same order of magnitude) while TIME should grow with modulus
size because each oracle call performs a bigger modular exponentiation.
"""
import csv
import os
import sys
import time
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bleichenbacher.rsa_core import RSAKey
from bleichenbacher.attack import attack_rsa_key, AttackStats

TRIALS = 3
BIT_SIZES = [128, 192, 256, 320, 384]
MESSAGE = b"hi"

rows = []
for bits in BIT_SIZES:
    queries_list, time_list = [], []
    for trial in range(TRIALS):
        key = RSAKey(bits=bits)
        ct = key.encrypt(MESSAGE)
        stats = AttackStats()
        t0 = time.time()
        recovered, stats = attack_rsa_key(key, ct, bits_required=16, stats=stats)
        t1 = time.time()
        assert recovered == MESSAGE
        queries_list.append(stats.queries)
        time_list.append(t1 - t0)
    mean_q = statistics.mean(queries_list)
    mean_t = statistics.mean(time_list)
    rows.append((bits, mean_q, statistics.pstdev(queries_list), mean_t, statistics.pstdev(time_list)))
    print(f"bits={bits:4d}  mean_queries={mean_q:9.0f}  mean_time={mean_t:7.2f}s")

out_path = os.path.join(os.path.dirname(__file__), "..", "figures", "bb_modulus_size.csv")
with open(out_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["bits", "mean_queries", "std_queries", "mean_time_s", "std_time_s"])
    w.writerows(rows)
print("wrote", out_path)
