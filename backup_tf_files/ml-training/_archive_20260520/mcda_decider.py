"""
mcda_decider.py
===============
Reads output/policy_scorecard.csv (produced by policy_scorer.py) and ranks
candidate baseline policies using TOPSIS (Multi-Criteria Decision Analysis).

Each policy is scored against weighted criteria:
  - catch_mean_across_variants  (maximise; primary efficacy signal)
  - catch_std_across_variants   (minimise; stability across placements)
  - catch_min_variant           (maximise; weakest-link guard)

Edit CRITERIA below to change weights or add metrics (FP rate, WCU cost, etc.
once those datasets are available).

Output:
  output/recommendations.csv   ranked policy list with composite score
"""
import csv
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "output")

# (column_name, direction, weight)
CRITERIA = [
    ("catch_mean_across_variants", "max", 0.55),
    ("catch_std_across_variants",  "min", 0.25),
    ("catch_min_variant",          "max", 0.20),
]


def topsis(matrix, weights, directions):
    n_alt = len(matrix)
    n_crit = len(matrix[0])
    col_norm = [math.sqrt(sum(matrix[i][j] ** 2 for i in range(n_alt))) for j in range(n_crit)]
    norm = [[matrix[i][j] / col_norm[j] if col_norm[j] else 0.0 for j in range(n_crit)] for i in range(n_alt)]
    w = [[norm[i][j] * weights[j] for j in range(n_crit)] for i in range(n_alt)]
    ideal = []
    anti = []
    for j in range(n_crit):
        col = [w[i][j] for i in range(n_alt)]
        if directions[j] == "max":
            ideal.append(max(col))
            anti.append(min(col))
        else:
            ideal.append(min(col))
            anti.append(max(col))
    d_pos = [math.sqrt(sum((w[i][j] - ideal[j]) ** 2 for j in range(n_crit))) for i in range(n_alt)]
    d_neg = [math.sqrt(sum((w[i][j] - anti[j]) ** 2 for j in range(n_crit))) for i in range(n_alt)]
    closeness = []
    for i in range(n_alt):
        denom = d_pos[i] + d_neg[i]
        closeness.append(d_neg[i] / denom if denom else 0.0)
    return closeness


def main():
    src = os.path.join(OUT_DIR, "policy_scorecard.csv")
    if not os.path.exists(src):
        print(f"ERROR: {src} not found. Run policy_scorer.py first.")
        return

    with open(src) as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        print("No policies in scorecard.")
        return

    weights = [w for _, _, w in CRITERIA]
    directions = [d for _, d, _ in CRITERIA]
    matrix = [[float(r[name]) for name, _, _ in CRITERIA] for r in rows]
    scores = topsis(matrix, weights, directions)

    ranked = sorted(zip(rows, scores), key=lambda x: -x[1])

    out = os.path.join(OUT_DIR, "recommendations.csv")
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "rank", "policy", "composite_score",
            "catch_mean", "catch_std", "catch_min_variant",
            "verdict",
        ])
        for rank, (row, score) in enumerate(ranked, 1):
            verdict = "PROD-CANDIDATE" if rank == 1 else "ALT"
            w.writerow([
                rank, row["policy"], round(score, 4),
                row["catch_mean_across_variants"],
                row["catch_std_across_variants"],
                row["catch_min_variant"],
                verdict,
            ])

    print("MCDA / TOPSIS ranking")
    print("=" * 78)
    print(f"{'Rank':<5} {'Policy':<18} {'Composite':<11} {'Catch%':<8} {'Std':<6} {'Min var%':<9} Verdict")
    print("-" * 78)
    for rank, (row, score) in enumerate(ranked, 1):
        verdict = "PROD-CANDIDATE" if rank == 1 else "ALT"
        print(f"{rank:<5} {row['policy']:<18} {score:<11.4f} "
              f"{row['catch_mean_across_variants']:<8} "
              f"{row['catch_std_across_variants']:<6} "
              f"{row['catch_min_variant']:<9} {verdict}")
    print()
    print("Weights:", {n: w for n, _, w in CRITERIA})
    print(f"Wrote: {out}")


if __name__ == "__main__":
    main()
