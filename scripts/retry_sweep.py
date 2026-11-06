"""
Retry budget sweep: how much enrichment survives a given failure rate.

Runs the real triage graph with the stub model (no GPU, no network) over the
whole corpus. Every lookup goes through FaultInjectingEnrichment at a nominal
failure rate, wrapped in ResilientEnrichment with a given retry budget. Each
budget is run over several seeds, because one seed on a small sample can
realize a failure rate well away from the nominal one.

Reports, per retry budget:
  - realized per-attempt failure rate (what the seeded generator actually did)
  - mean lookup completeness (lookups returned / lookups requested)
  - mean number of alerts with at least one missing lookup
  - expected completeness from the realized rate: 1 - p**attempts

Writes results/retry-sweep.json. Deterministic: the same arguments always give
the same file.

    python scripts/retry_sweep.py
    python scripts/retry_sweep.py --rate 0.4 --attempts 1 2 3 5 --seeds 20
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from soc_triage.enrichment.base import ResilientEnrichment, RetryPolicy
from soc_triage.enrichment.stubs import FaultInjectingEnrichment, LocalEnrichment
from soc_triage.evaluation.runner import corpus_fingerprint, load_corpus
from soc_triage.pipeline.graph import TriagePipeline
from soc_triage.pipeline.model import StubModel


class CountingFaults(FaultInjectingEnrichment):
    """Counts every attempt and every injected failure."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attempts = 0
        self.failures = 0

    def _maybe_fail(self, method: str) -> None:
        self.attempts += 1
        try:
            super()._maybe_fail(method)
        except Exception:
            self.failures += 1
            raise


def run_once(alerts, rate: float, attempts: int, seed: int) -> dict:
    faults = CountingFaults(LocalEnrichment(alerts), failure_rate=rate, seed=seed)
    pipeline = TriagePipeline(ResilientEnrichment(faults, RetryPolicy(max_attempts=attempts)),
                              StubModel())
    requested = returned = degraded = 0
    for alert in alerts:
        case, _ = pipeline.run(alert)
        requested += case.enrichment_requested
        returned += case.enrichment_returned
        degraded += case.enrichment_returned < case.enrichment_requested
    return {"seed": seed, "lookups_requested": requested, "lookups_returned": returned,
            "completeness": returned / requested, "degraded_alerts": degraded,
            "attempts_made": faults.attempts, "failures_injected": faults.failures,
            "realized_failure_rate": faults.failures / faults.attempts}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--rate", type=float, default=0.4)
    ap.add_argument("--attempts", type=int, nargs="+", default=[1, 2, 3, 5])
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--out", default=str(REPO_ROOT / "results" / "retry-sweep.json"))
    args = ap.parse_args()

    alerts, _ = load_corpus()
    rows = []
    for k in args.attempts:
        runs = [run_once(alerts, args.rate, k, seed) for seed in range(args.seeds)]
        n = len(runs)
        realized = sum(r["realized_failure_rate"] for r in runs) / n
        rows.append({
            "attempts": k,
            "mean_realized_failure_rate": round(realized, 4),
            "mean_completeness": round(sum(r["completeness"] for r in runs) / n, 4),
            "expected_completeness_from_realized_rate": round(1 - realized ** k, 4),
            "nominal_failure_after_retries": round(args.rate ** k, 4),
            "mean_degraded_alerts": round(sum(r["degraded_alerts"] for r in runs) / n, 2),
            "runs": runs,
        })
        print(f"attempts {k}: realized failure {realized:.1%}, completeness "
              f"{rows[-1]['mean_completeness']:.1%} (expected {rows[-1]['expected_completeness_from_realized_rate']:.1%}), "
              f"alerts degraded {rows[-1]['mean_degraded_alerts']:.1f} of {len(alerts)}")

    out = {"corpus_fingerprint": corpus_fingerprint(), "alerts": len(alerts),
           "nominal_failure_rate": args.rate, "seeds": args.seeds,
           "model": "stub", "results": rows}
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {Path(args.out).relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
