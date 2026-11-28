"""Check the case set and show where the pattern engine disagrees with labels.

    python -m eval.validate            # all cases
    python -m eval.validate D03 D04    # cases whose id starts with these"""
from __future__ import annotations

import sys

from app.rules import run_pattern_checks

from .dataset import GAP, CaseError, load_cases


def main(argv: list[str]) -> int:
    try:
        cases = load_cases(only=argv or None)
    except CaseError as exc:
        print(exc)
        return 1
    for c in cases:
        found = {f.rule_id: f for f in run_pattern_checks(c.docs, c.disposition, c.discharge_date, c.today)}
        diffs = []
        for rid, exp in c.expected.items():
            got = found[rid].status
            if not c.ok(rid, got):
                worst = "FALSE PASS" if exp in GAP and got in ("pass", "not_applicable") else ""
                diffs.append(f"    {rid}: expected {exp}, pattern says {got} {worst}".rstrip())
        print(f"{c.id} [{c.category}] {len(c.docs)} doc(s): {'agrees with labels' if not diffs else str(len(diffs)) + ' disagreement(s)'}")
        print("\n".join(diffs)) if diffs else None
    print(f"\n{len(cases)} case(s) valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
