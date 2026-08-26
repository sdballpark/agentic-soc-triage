"""Running an evaluation.

Walks the corpus, triages each alert, scores the result, and writes a run
artifact. The artifact is the point: a number in a README that nobody can
reproduce is a claim, not a measurement. Each run records the model, the
prompt version, the corpus hash, and every individual score, so two runs can
be diffed to find exactly which alerts changed.

Execution is serial on purpose. Concurrency would make wall-clock time better
and reproducibility worse, and a local model on one GPU is the bottleneck
anyway.

Anything that exposes the pipeline to the corpus lives here rather than in
soc_triage/pipeline/, because this module reads the answer key and the
pipeline package is forbidden from doing so.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Protocol

from soc_triage.evaluation.labels import AlertLabel, assert_join_integrity, load_labels
from soc_triage.evaluation.metrics import EvalReport, score_alert
from soc_triage.pipeline.state import CaseArtifact

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ALERTS = REPO_ROOT / "data" / "alerts.json"
DEFAULT_LABELS = REPO_ROOT / "data" / "labels.json"
DEFAULT_RESULTS_DIR = REPO_ROOT / "results"


class TriageRunner(Protocol):
    """Anything that can disposition an alert: a pipeline or a baseline."""

    name: str

    def run(self, alert: dict[str, Any]) -> tuple[Optional[CaseArtifact], list[str]]: ...


def corpus_fingerprint(alerts_path: Path = DEFAULT_ALERTS) -> str:
    """Short hash of the corpus a run was scored against.

    Without this, comparing two runs assumes they saw the same alerts. That
    assumption broke once already during this build.
    """
    digest = hashlib.sha256(alerts_path.read_bytes()).hexdigest()
    return digest[:12]


def load_corpus(
    alerts_path: Path = DEFAULT_ALERTS, labels_path: Path = DEFAULT_LABELS
) -> tuple[list[dict], dict[str, AlertLabel]]:
    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    labels = load_labels(labels_path)
    assert_join_integrity({a["alert_id"] for a in alerts}, labels)
    return alerts, labels


def run_eval(
    runner: TriageRunner,
    *,
    alerts: Optional[Iterable[dict]] = None,
    labels: Optional[dict[str, AlertLabel]] = None,
    run_label: str = "eval",
    limit: Optional[int] = None,
    progress: Optional[Callable[[int, int, str], None]] = None,
) -> EvalReport:
    """Triage every alert and score the results."""
    if alerts is None or labels is None:
        alerts, labels = load_corpus()
    alerts = list(alerts)
    if limit:
        alerts = alerts[:limit]

    scores = []
    prompt_version = ""
    for index, alert in enumerate(alerts, start=1):
        case, _trail = runner.run(alert)
        if case is not None and not prompt_version:
            prompt_version = case.prompt_version
        scores.append(score_alert(case, labels[alert["alert_id"]], alert["tactic"]))
        if progress:
            progress(index, len(alerts), alert["alert_id"])

    return EvalReport(
        run_label=run_label,
        model_name=getattr(runner, "name", "unknown"),
        prompt_version=prompt_version or "n/a",
        corpus_size=len(alerts),
        scores=scores,
    )


def write_run(
    report: EvalReport,
    results_dir: Path = DEFAULT_RESULTS_DIR,
    *,
    elapsed_seconds: float = 0.0,
    notes: str = "",
) -> Path:
    """Persist a run as JSON, including the headline metrics.

    Metrics are stored as values rather than recomputed on read, so a run
    artifact stays meaningful even if the scoring code later changes. If a
    metric definition moves, the old numbers still say what they said.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_label": report.run_label,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model_name": report.model_name,
        "prompt_version": report.prompt_version,
        "corpus_size": report.corpus_size,
        "corpus_fingerprint": corpus_fingerprint(),
        "elapsed_seconds": round(elapsed_seconds, 1),
        "notes": notes,
        "metrics": {
            "false_close_rate": report.false_close_rate,
            "false_positive_rate": report.false_positive_rate,
            "strict_accuracy": report.strict_accuracy,
            "lenient_accuracy": report.lenient_accuracy,
            "over_abstention_rate": report.over_abstention_rate,
            "mean_enrichment_completeness": report.mean_enrichment_completeness,
            "injection_compliance_rate": report.injection_compliance_rate,
            "injection_detection_rate": report.injection_detection_rate,
            "injection_false_alarm_rate": report.injection_false_alarm_rate,
        },
        "by_tactic": {
            tactic: {"correct": r.correct, "total": r.total, "accuracy": r.accuracy}
            for tactic, r in sorted(report.by_tactic().items())
        },
        "by_slice": {
            name: {"correct": r.correct, "total": r.total, "accuracy": r.accuracy}
            for name, r in sorted(report.by_slice().items())
        },
        "outcome_counts": report.outcome_counts(),
        "scores": [json.loads(s.model_dump_json()) for s in report.scores],
    }

    path = results_dir / f"{report.run_label}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def timed_run(runner: TriageRunner, **kwargs) -> tuple[EvalReport, float]:
    started = time.monotonic()
    report = run_eval(runner, **kwargs)
    return report, time.monotonic() - started
