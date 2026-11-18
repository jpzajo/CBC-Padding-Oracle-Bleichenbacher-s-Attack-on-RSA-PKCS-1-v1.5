"""
Experiment: how many oracle queries does the Vaudenay attack need as a
function of the number of ciphertext blocks? Each block costs the same
expected number of queries (about 256 * 16 / 2 for the decryption
direction; see analysis in the report), so this should be close to
linear in the number of blocks.
"""
import csv
import statistics
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from padding_oracle.server import CookieService
from padding_oracle import attack as A

TRIALS = 5
BLOCK_COUNTS = [1, 2, 3, 4, 5, 6, 8]

rows = []
for nblocks in BLOCK_COUNTS:
    queries_list = []
    for trial in range(TRIALS):
        svc = CookieService(vulnerable=True)
        # (nblocks*16 - 1) data bytes + padding -> exactly nblocks blocks
        plaintext = os.urandom(nblocks * 16 - 1)
        iv, ct, _ = svc.issue_cookie(plaintext)

        def oracle(prev, target):
            return svc.padding_oracle(prev, target)

        stats = A.AttackStats()
        recovered = A.decrypt(oracle, iv, ct, stats)
        from padding_oracle.aes_core import pkcs7_unpad
        assert pkcs7_unpad(recovered) == plaintext
        queries_list.append(stats.queries)
    mean_q = statistics.mean(queries_list)
    std_q = statistics.pstdev(queries_list)
    per_block = mean_q / nblocks
    rows.append((nblocks, mean_q, std_q, per_block))
    print(f"blocks={nblocks}  mean_queries={mean_q:.0f}  std={std_q:.0f}  per_block={per_block:.0f}")

out_path = os.path.join(os.path.dirname(__file__), "..", "figures", "padding_oracle_cost.csv")
with open(out_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["blocks", "mean_queries", "std_queries", "queries_per_block"])
    w.writerows(rows)
print("wrote", out_path)
