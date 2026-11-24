import csv
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

FIG_DIR = os.path.join(os.path.dirname(__file__), "..", "figures")


def read_csv(name):
    path = os.path.join(FIG_DIR, name)
    with open(path) as f:
        reader = csv.DictReader(f)
        return [{k: float(v) for k, v in row.items()} for row in reader]


def plot_padding_oracle_cost():
    rows = read_csv("padding_oracle_cost.csv")
    x = [r["blocks"] for r in rows]
    y = [r["mean_queries"] for r in rows]
    yerr = [r["std_queries"] for r in rows]

    plt.figure(figsize=(5.5, 4))
    plt.errorbar(x, y, yerr=yerr, marker="o", capsize=3, color="#1f6feb")
    plt.xlabel("Ciphertext length (blocks)")
    plt.ylabel("Oracle queries (mean of 5 trials)")
    plt.title("CBC padding-oracle attack: cost vs. plaintext length")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "padding_oracle_cost.png"), dpi=150)
    plt.close()


def plot_bb_modulus_size():
    rows = read_csv("bb_modulus_size.csv")
    x = [r["bits"] for r in rows]
    q = [r["mean_queries"] for r in rows]
    qerr = [r["std_queries"] for r in rows]
    t = [r["mean_time_s"] for r in rows]

    fig, ax1 = plt.subplots(figsize=(6, 4.2))
    ax1.errorbar(x, q, yerr=qerr, marker="o", color="#1f6feb", label="Oracle queries")
    ax1.set_xlabel("RSA modulus size (bits)")
    ax1.set_ylabel("Oracle queries (mean of 3 trials)", color="#1f6feb")
    ax1.tick_params(axis="y", labelcolor="#1f6feb")
    ax1.grid(alpha=0.3)

    ax2 = ax1.twinx()
    ax2.plot(x, t, marker="s", color="#d1242f", label="Wall-clock time")
    ax2.set_ylabel("Wall-clock time (s)", color="#d1242f")
    ax2.tick_params(axis="y", labelcolor="#d1242f")

    plt.title("Bleichenbacher attack: queries stay flat, time grows with modulus size")
    fig.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "bb_modulus_size.png"), dpi=150)
    plt.close()


def plot_bb_noisy_oracle():
    rows = read_csv("bb_noisy_oracle.csv")
    # Plot against the index (evenly spaced) rather than the raw p_error
    # value (unevenly spaced, near-zero), so points aren't crowded together
    # and so we can label each one with just its own value, at the
    # precision it actually needs, instead of letting matplotlib pick
    # shared linear ticks across the full 0-0.002 range.
    x_pos = list(range(len(rows)))
    y = [r["success_rate"] for r in rows]
    labels = [f"{r['p_error'] * 100:g}%" for r in rows]

    plt.figure(figsize=(5.5, 4))
    plt.plot(x_pos, y, marker="o", color="#d1242f")
    plt.xticks(x_pos, labels)
    plt.xlabel("Per-query oracle error rate")
    plt.ylabel("Attack success rate")
    plt.ylim(-0.05, 1.05)
    plt.title("Bleichenbacher attack collapses under a noisy oracle")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "bb_noisy_oracle.png"), dpi=150)
    plt.close()


if __name__ == "__main__":
    plot_padding_oracle_cost()
    plot_bb_modulus_size()
    plot_bb_noisy_oracle()
    print("all plots written")
