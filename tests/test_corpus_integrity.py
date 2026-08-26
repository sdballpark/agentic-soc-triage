"""Corpus reproducibility invariants.

These exist because of a real failure during the build: a corpus was committed
that had been generated from a version of templates.py that was not in the
commit. Nothing errored. Every count looked correct. The only tell was a
single summary number reading 0 instead of 4.

That class of drift is silent and it invalidates every measurement, because
the numbers in the README would describe data nobody can regenerate. So the
property is enforced here rather than trusted.

The gate: regenerate from the committed seed and require the result to match
the committed files exactly. If templates, environment, injections, or the
catalog change without regenerating, this fails.
"""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from generate_corpus import CORPUS_SEED, generate  # noqa: E402

from soc_triage.corpus.alert import Alert  # noqa: E402
from soc_triage.evaluation.labels import (  # noqa: E402
    CorpusSlice,
    assert_join_integrity,
    load_labels,
)
from soc_triage.corpus.techniques import ADVERSARIAL_COUNT, CATALOG  # noqa: E402

DATA_DIR = REPO_ROOT / "data"
ALERTS_PATH = DATA_DIR / "alerts.json"
LABELS_PATH = DATA_DIR / "labels.json"


@pytest.fixture(scope="module")
def committed_alerts() -> list[dict]:
    return json.loads(ALERTS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def regenerated():
    return generate(CORPUS_SEED)


def test_committed_corpus_matches_regeneration(committed_alerts, regenerated):
    """The committed alerts must be exactly what the committed code produces."""
    alerts, _ = regenerated
    fresh = [json.loads(a.model_dump_json(exclude_none=True)) for a in alerts]

    assert len(fresh) == len(committed_alerts), (
        f"regenerated {len(fresh)} alerts, committed file has "
        f"{len(committed_alerts)}. Run scripts/generate_corpus.py."
    )

    for expected, actual in zip(fresh, committed_alerts):
        assert expected == actual, (
            f"{expected['alert_id']} differs from the committed corpus. "
            "Corpus code changed without regenerating; run "
            "scripts/generate_corpus.py and commit the result."
        )


def test_committed_labels_match_regeneration(regenerated):
    _, labels = regenerated
    fresh = [json.loads(l.model_dump_json(exclude_none=True)) for l in labels]
    committed = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    assert fresh == committed, "labels.json is stale; run scripts/generate_corpus.py."


def test_join_holds_on_committed_files(committed_alerts):
    """Every alert has exactly one label and vice versa, on disk.

    Checked against the files rather than in-memory objects, because a
    mismatch here would silently change the denominator of every metric.
    """
    labels = load_labels(LABELS_PATH)
    assert_join_integrity({a["alert_id"] for a in committed_alerts}, labels)


def test_alerts_carry_no_answers(committed_alerts):
    """alerts.json must not contain any answer-key field, at any depth."""
    banned = {
        "disposition", "corpus_slice", "rationale",
        "abstention_acceptable", "injected_field",
    }

    def walk(node, path=""):
        if isinstance(node, dict):
            for key, value in node.items():
                assert key not in banned, f"answer-key field '{key}' found at {path}"
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")

    for alert in committed_alerts:
        walk(alert, alert["alert_id"])


def test_committed_alerts_validate_against_the_models(committed_alerts):
    """Every record parses back into a typed Alert.

    This exercises the discriminated union: a record whose EventSchema does
    not match its fields fails here rather than at pipeline runtime.
    """
    for raw in committed_alerts:
        alert = Alert.model_validate(raw)
        assert alert.event.EventSchema == raw["event"]["EventSchema"]


def test_slice_distribution_matches_the_catalog():
    """Slice counts must follow techniques.py, not drift from it."""
    labels = load_labels(LABELS_PATH)
    counts = {s: 0 for s in CorpusSlice}
    for label in labels.values():
        counts[label.corpus_slice] += 1

    expected_malicious = sum(t.malicious_count for t in CATALOG)
    expected_benign = sum(t.benign_count for t in CATALOG)

    assert counts[CorpusSlice.MALICIOUS] == expected_malicious
    assert counts[CorpusSlice.BENIGN] == expected_benign
    assert counts[CorpusSlice.ADVERSARIAL] == ADVERSARIAL_COUNT


def test_every_adversarial_payload_is_actually_present(committed_alerts):
    """An injection label must correspond to a real payload in the record.

    Without this, a bug in field selection would leave the adversarial slice
    carrying no injections, and injection-resistance would score 100% against
    alerts that contain nothing to resist.
    """
    alerts = {a["alert_id"]: a for a in committed_alerts}
    labels = load_labels(LABELS_PATH)

    adversarial = [l for l in labels.values() if l.corpus_slice is CorpusSlice.ADVERSARIAL]
    assert adversarial, "no adversarial alerts in the corpus"

    for label in adversarial:
        event = alerts[label.alert_id]["event"]
        field = label.injected_field
        assert field in event, f"{label.alert_id}: {field} absent from the record"
        assert str(event[field]).strip(), f"{label.alert_id}: {field} is empty"


def test_abstention_measure_has_something_to_measure():
    """At least one alert where abstaining is defensible.

    A metric that can only ever return zero is worse than no metric: it
    reports a number that looks like a result.
    """
    labels = load_labels(LABELS_PATH)
    acceptable = [l for l in labels.values() if l.abstention_acceptable]
    assert acceptable, (
        "no alert marked abstention_acceptable; the abstention metric would "
        "be vacuous"
    )
