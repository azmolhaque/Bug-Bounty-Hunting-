#!/usr/bin/env python3
"""
Rank Intigriti programs by the number the rubric calls most predictive and that
we have never once actually used: ACCEPTED PER RESEARCHER.

Every target chosen so far was picked by accident — Exoscale because it was
interesting, Adobe because it was large, Coveo because a scanner happened to hit
it, Meta because its payout table looked good. Five programs, zero findings.

Exoscale's ratio was 0.16. That number was available before we started and was
read optimistically. The rubric's own warning: a low ratio means HARD, not
untouched.

Paste the lines, run it, get a ranking.

usage:
  python3 rank-programs.py <<'EOF'
  Coveo | 412 | 1850 | 96 | 664
  Acme  | 88  | 210  | 71 | 1200
  EOF

format:
  name | researchers | submissions received | accepted submissions | avg payout
"""
import sys


def main():
    rows = []
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            print(f"  ?? skipped (need 5 fields): {line}")
            continue
        name = parts[0]
        try:
            researchers, submissions, accepted = (int(float(p.replace(",", "")))
                                                  for p in parts[1:4])
            payout = float(parts[4].replace(",", "").replace("$", "").replace("€", ""))
        except ValueError:
            print(f"  ?? skipped (non-numeric): {line}")
            continue

        apr = accepted / researchers if researchers else 0.0     # the headline number
        acc_rate = accepted / submissions if submissions else 0.0  # signal quality
        # Expected value per researcher who engages, very rough.
        ev = apr * payout
        rows.append((apr, acc_rate, ev, name, researchers, submissions, accepted, payout))

    if not rows:
        print("no usable rows"); return

    rows.sort(reverse=True)
    print(f"\n{'program':<26}{'acc/res':>9}{'acc-rate':>10}{'EV/res':>10}   verdict")
    print("-" * 78)
    for apr, acc_rate, ev, name, r, s, a, p in rows:
        if apr >= 0.6:
            v = "PURSUE — above rubric threshold"
        elif apr >= 0.35:
            v = "maybe — better than anything tried so far"
        elif apr >= 0.20:
            v = "weak"
        else:
            v = f"SKIP — at or below Exoscale (0.16)"
        print(f"{name[:26]:<26}{apr:>9.2f}{acc_rate:>10.2f}{ev:>10.0f}   {v}")

    print("\nacc/res  = accepted submissions per researcher. The rubric's key metric.")
    print("acc-rate = accepted / submitted. Low means a noisy, heavily-duped program.")
    print("EV/res   = acc/res x average payout. Rough money-per-engaged-researcher.")
    print("\nStill apply the six hard gates to whatever ranks highest:")
    print("  free account · two accounts obtainable · multi-tenant · API in scope")
    print("  · broken access control IN scope · not a security/infra vendor")


if __name__ == "__main__":
    main()
