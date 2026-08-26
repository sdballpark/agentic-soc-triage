"""Generate the synthetic corpus and its answer key.

Run:  python scripts/generate_corpus.py

Writes data/alerts.json (what the pipeline sees) and data/labels.json (what
the harness scores against). Both are committed, so a reviewer can read the
corpus on GitHub without running anything, and the numbers in the README refer
to a specific file anyone can inspect.

Why this lives in scripts/ rather than soc_triage/corpus/:

The label isolation test forbids soc_triage/corpus/ from importing
soc_triage/evaluation/. A generator inside the package would have to break
that rule to write labels. Generation is a build-time tool, not runtime
pipeline code, so it belongs outside the packages the pipeline imports. The
gate caught this design problem before it became a hole.

Determinism: everything derives from CORPUS_SEED. Regenerating with the same
seed reproduces the corpus byte for byte, which is what makes eval numbers
comparable across commits.
"""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from soc_triage.corpus.alert import Alert  # noqa: E402
from soc_triage.corpus.injections import (  # noqa: E402
    ATTACKER_CONTROLLED_FIELDS,
    InjectionDirection,
    by_direction,
)
from soc_triage.corpus.techniques import ADVERSARIAL_COUNT, CATALOG  # noqa: E402
from soc_triage.corpus.templates import TEMPLATES, TemplateResult, Variant  # noqa: E402
from soc_triage.disposition import Disposition  # noqa: E402
from soc_triage.evaluation.labels import (  # noqa: E402
    AlertLabel,
    CorpusSlice,
    assert_join_integrity,
)

CORPUS_SEED = 20260826
CORPUS_END = datetime(2026, 8, 26, 18, 0, tzinfo=timezone.utc)
CORPUS_WINDOW = timedelta(days=7)

DATA_DIR = REPO_ROOT / "data"


def _timestamp(rng: random.Random) -> datetime:
    """A time within the corpus window, to the second."""
    offset = timedelta(seconds=rng.randrange(int(CORPUS_WINDOW.total_seconds())))
    return (CORPUS_END - CORPUS_WINDOW + offset).replace(microsecond=0)


def _tactic_for(technique_id: str) -> str:
    return next(t.tactic.value for t in CATALOG if t.technique_id == technique_id)


def _build_alert(alert_id: str, technique_id: str, result: TemplateResult) -> Alert:
    return Alert(
        alert_id=alert_id,
        title=result.title,
        severity=result.severity,
        created_time=result.event.TimeGenerated,
        technique_id=technique_id,
        tactic=_tactic_for(technique_id),
        entity_summary=result.entity_summary,
        event=result.event,
    )


def _inject(alert: Alert, payload: str, rng: random.Random) -> tuple[Alert, str]:
    """Embed a payload in an attacker-controlled field.

    The event is rebuilt through its model rather than mutated, so an
    injection that produced an invalid record would fail here rather than
    silently land in the corpus.
    """
    schema = alert.event.EventSchema
    candidates = ATTACKER_CONTROLLED_FIELDS[schema]
    field = rng.choice(candidates)

    data = alert.event.model_dump()
    existing = data.get(field)
    data[field] = f"{existing} {payload}" if existing else payload

    rebuilt = type(alert.event)(**data)
    return alert.model_copy(update={"event": rebuilt}), field


def generate(seed: int = CORPUS_SEED) -> tuple[list[Alert], list[AlertLabel]]:
    rng = random.Random(seed)
    alerts: list[Alert] = []
    labels: list[AlertLabel] = []
    counter = 0

    def next_id() -> str:
        nonlocal counter
        counter += 1
        return f"alert-{counter:04d}"

    # --- Base corpus: malicious and benign, per the catalog counts ---
    for technique in CATALOG:
        for variant, count, slice_, disposition in (
            (Variant.MALICIOUS, technique.malicious_count,
             CorpusSlice.MALICIOUS, Disposition.ESCALATE),
            (Variant.BENIGN, technique.benign_count,
             CorpusSlice.BENIGN, Disposition.CLOSE_BENIGN),
        ):
            builder = TEMPLATES.get((technique.technique_id, variant))
            if builder is None or count == 0:
                continue
            for _ in range(count):
                result = builder(rng, _timestamp(rng))
                alert_id = next_id()
                alerts.append(_build_alert(alert_id, technique.technique_id, result))
                labels.append(AlertLabel(
                    alert_id=alert_id,
                    disposition=disposition,
                    technique_id=technique.technique_id,
                    corpus_slice=slice_,
                    rationale=result.rationale,
                    abstention_acceptable=result.abstention_acceptable,
                ))

    # --- Adversarial slice: injections riding inside ordinary alerts ---
    toward_close = by_direction(InjectionDirection.TOWARD_CLOSE)
    toward_escalate = by_direction(InjectionDirection.TOWARD_ESCALATE)

    malicious_techniques = [t.technique_id for t in CATALOG]
    benign_techniques = [t.technique_id for t in CATALOG if t.benign_count > 0]

    plan = [
        (inj, Variant.MALICIOUS, Disposition.ESCALATE,
         malicious_techniques[i % len(malicious_techniques)])
        for i, inj in enumerate(toward_close)
    ] + [
        (inj, Variant.BENIGN, Disposition.CLOSE_BENIGN,
         benign_techniques[i % len(benign_techniques)])
        for i, inj in enumerate(toward_escalate)
    ]

    if len(plan) != ADVERSARIAL_COUNT:
        raise ValueError(
            f"adversarial plan has {len(plan)} entries, catalog expects {ADVERSARIAL_COUNT}"
        )

    for injection, variant, disposition, technique_id in plan:
        builder = TEMPLATES[(technique_id, variant)]
        result = builder(rng, _timestamp(rng))
        alert_id = next_id()
        alert = _build_alert(alert_id, technique_id, result)
        alert, field = _inject(alert, injection.payload, rng)
        alerts.append(alert)
        labels.append(AlertLabel(
            alert_id=alert_id,
            disposition=disposition,
            technique_id=technique_id,
            corpus_slice=CorpusSlice.ADVERSARIAL,
            rationale=(
                f"{result.rationale} The alert additionally carries a "
                f"{injection.category.value} payload in {field}; the correct "
                "disposition follows the underlying activity, not the injected text."
            ),
            abstention_acceptable=result.abstention_acceptable,
            injected_field=field,
        ))

    return alerts, labels


def write_corpus(alerts: list[Alert], labels: list[AlertLabel], data_dir: Path) -> None:
    """Verify the join, then write. Never write an inconsistent pair."""
    assert_join_integrity({a.alert_id for a in alerts}, {l.alert_id: l for l in labels})

    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "alerts.json").write_text(
        json.dumps([json.loads(a.model_dump_json(exclude_none=True)) for a in alerts], indent=2)
        + "\n",
        encoding="utf-8",
    )
    (data_dir / "labels.json").write_text(
        json.dumps([json.loads(l.model_dump_json(exclude_none=True)) for l in labels], indent=2)
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    alerts, labels = generate()
    write_corpus(alerts, labels, DATA_DIR)

    from collections import Counter

    slices = Counter(l.corpus_slice.value for l in labels)
    tactics = Counter(a.tactic for a in alerts)
    schemas = Counter(a.event.EventSchema for a in alerts)

    print(f"wrote {len(alerts)} alerts and {len(labels)} labels to {DATA_DIR}")
    print("\nslices:  ", dict(slices))
    print("tactics: ", dict(tactics))
    print("schemas: ", dict(schemas))
    print("abstention-acceptable:", sum(1 for l in labels if l.abstention_acceptable))


if __name__ == "__main__":
    main()
