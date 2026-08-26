"""Run an evaluation.

  python scripts/run_eval.py --mode baseline-severity
  python scripts/run_eval.py --mode baseline-threat_risk
  python scripts/run_eval.py --mode stub --limit 5
  python scripts/run_eval.py --mode model --model-name qwen2.5-14b-instruct
  python scripts/run_eval.py --mode model --enrichment-failure-rate 0.25

The last form is the interesting one. It degrades enrichment deliberately and
measures what happens to accuracy, which answers a question the JD implies
but most projects never ask: how does this behave when a dependency is
flaky rather than absent.

Results land in results/ and are committed, so the numbers in the README
correspond to a file anyone can open. The corpus fingerprint is recorded in
each run, so two results are only comparable if they scored the same alerts.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from soc_triage.enrichment.base import ResilientEnrichment, RetryPolicy  # noqa: E402
from soc_triage.enrichment.stubs import (  # noqa: E402
    FaultInjectingEnrichment,
    LocalEnrichment,
)
from soc_triage.evaluation.baseline import BASELINES, BaselinePolicy  # noqa: E402
from soc_triage.evaluation.runner import (  # noqa: E402
    corpus_fingerprint,
    load_corpus,
    timed_run,
    write_run,
)
from soc_triage.pipeline.graph import TriagePipeline  # noqa: E402
from soc_triage.pipeline.model import (  # noqa: E402
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    OpenAICompatibleModel,
    StubModel,
)


def build_runner(args, alerts):
    if args.mode.startswith("baseline-"):
        return BaselinePolicy(args.mode.removeprefix("baseline-"))

    enrichment = LocalEnrichment(alerts)
    if args.enrichment_failure_rate:
        enrichment = ResilientEnrichment(
            FaultInjectingEnrichment(
                enrichment,
                failure_rate=args.enrichment_failure_rate,
                seed=args.seed,
            ),
            RetryPolicy(max_attempts=args.retries),
        )
    else:
        enrichment = ResilientEnrichment(enrichment, RetryPolicy(max_attempts=args.retries))

    if args.mode == "stub":
        return TriagePipeline(enrichment, StubModel())

    model = OpenAICompatibleModel(
        base_url=args.base_url,
        model=args.model_name,
        temperature=args.temperature,
    )
    return TriagePipeline(enrichment, model)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the triage pipeline.")
    parser.add_argument(
        "--mode",
        default="baseline-severity",
        choices=["stub", "model"] + [f"baseline-{n}" for n in sorted(BASELINES)],
    )
    parser.add_argument("--limit", type=int, default=None,
                        help="score only the first N alerts")
    parser.add_argument("--enrichment-failure-rate", type=float, default=0.0,
                        help="fail this fraction of lookups, deterministically")
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--seed", type=int, default=0,
                        help="seed for deterministic fault injection")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--model-name", default=DEFAULT_MODEL)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--run-label", default=None)
    parser.add_argument("--results-dir", default=str(REPO_ROOT / "results"))
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    alerts, labels = load_corpus()
    runner = build_runner(args, alerts)

    label = args.run_label or args.mode
    if args.enrichment_failure_rate:
        label += f"-degraded{int(args.enrichment_failure_rate * 100)}"

    print(f"corpus {corpus_fingerprint()} | {len(alerts)} alerts | mode {args.mode}")
    if args.mode == "model":
        print(f"model {args.model_name} at {args.base_url}")
    print()

    def progress(done: int, total: int, alert_id: str) -> None:
        if args.quiet:
            return
        end = "\n" if done == total else "\r"
        print(f"  {done:>3}/{total}  {alert_id}", end=end, flush=True)

    report, elapsed = timed_run(
        runner, alerts=alerts, labels=labels, run_label=label,
        limit=args.limit, progress=progress,
    )

    print()
    print(report.summary())
    print(f"\nelapsed {elapsed:.1f}s")

    if not args.no_write:
        notes = f"mode={args.mode}"
        if args.enrichment_failure_rate:
            notes += f", enrichment_failure_rate={args.enrichment_failure_rate}, seed={args.seed}"
        path = write_run(report, Path(args.results_dir),
                         elapsed_seconds=elapsed, notes=notes)
        print(f"wrote {path.relative_to(REPO_ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
