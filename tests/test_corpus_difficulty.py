"""Corpus difficulty invariants.

These exist because of a defect that nearly shipped. The first corpus assigned
severity by variant -- malicious got High or Medium, benign got Low. Every
other gate passed: it generated cleanly, reproduced exactly, leaked no
answers, and every alert was solvable. It was still worthless, because a
one-line rule reading EventSeverity scored 100%.

A benchmark whose answers are recoverable from one field measures field
reading. Nothing here checks that the pipeline is good; these check that the
corpus is capable of telling the difference.

The naive baselines are the instrument. If they climb toward perfect, the
corpus has developed a shortcut and these tests fail.
"""

import json
from collections import Counter, defaultdict
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

from soc_triage.evaluation.baseline import BASELINES, BaselinePolicy  # noqa: E402
from soc_triage.evaluation.labels import CorpusSlice, load_labels  # noqa: E402
from soc_triage.evaluation.metrics import EvalReport, score_alert  # noqa: E402

ALERTS_PATH = REPO_ROOT / "data" / "alerts.json"
LABELS_PATH = REPO_ROOT / "data" / "labels.json"

# A naive rule scoring above this means the corpus has a shortcut in it.
BASELINE_CEILING = 0.85

# Techniques that carry both a malicious and a benign variant. These are where
# the corpus actually tests reasoning, so their detection metadata must match.
MATCHED_PAIR_TECHNIQUES = ("T1078", "T1059.001", "T1053.005", "T1087.002", "T1046")


@pytest.fixture(scope="module")
def alerts() -> list[dict]:
    return json.loads(ALERTS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def labels():
    return load_labels(LABELS_PATH)


@pytest.mark.parametrize("baseline_name", sorted(BASELINES))
def test_naive_baselines_cannot_solve_the_corpus(baseline_name, alerts, labels):
    """A rule that reads one field must not do well.

    This is the test that would have caught the original defect. It failed
    nowhere else: the corpus was internally consistent, reproducible, and
    fully solvable. It was simply trivial.
    """
    policy = BaselinePolicy(baseline_name)
    scores = [
        score_alert(policy.run(a)[0], labels[a["alert_id"]], a["tactic"]) for a in alerts
    ]
    report = EvalReport(
        run_label=baseline_name, model_name=policy.name, prompt_version="n/a",
        corpus_size=len(scores), scores=scores,
    )
    assert report.strict_accuracy < BASELINE_CEILING, (
        f"the {baseline_name} baseline scores {report.strict_accuracy:.1%}. "
        "Ground truth has become recoverable from a single field, so every "
        "metric this harness reports would measure field reading rather than "
        "triage."
    )


def test_matched_pairs_share_detection_metadata(alerts, labels):
    """Paired techniques must be indistinguishable on detection alone.

    The same rule fires with the same severity whether an administrator or an
    attacker ran the command. If these diverge, the pair stops testing
    reasoning and starts testing metadata lookup.
    """
    for technique in MATCHED_PAIR_TECHNIQUES:
        grouped = defaultdict(set)
        for alert in alerts:
            if alert["technique_id"] != technique:
                continue
            if labels[alert["alert_id"]].corpus_slice is CorpusSlice.ADVERSARIAL:
                continue
            event = alert["event"]
            slice_name = labels[alert["alert_id"]].corpus_slice.value
            grouped[slice_name].add((
                alert["severity"],
                event.get("RuleName") or event.get("NetworkRuleName"),
                event.get("ThreatRiskLevel"),
                event.get("ThreatConfidence"),
            ))

        assert set(grouped) == {"malicious", "benign"}, (
            f"{technique}: expected both variants, found {sorted(grouped)}"
        )
        assert grouped["malicious"] == grouped["benign"], (
            f"{technique}: detection metadata differs between variants.\n"
            f"  malicious: {grouped['malicious']}\n"
            f"  benign:    {grouped['benign']}\n"
            "The pair is separable without reasoning about context."
        )


@pytest.mark.parametrize("field", ["severity"])
def test_severity_does_not_determine_disposition(field, alerts, labels):
    """At least one severity level must contain both outcomes.

    High-only-escalate is acceptable: some detections genuinely have no
    benign analogue. What is not acceptable is every level mapping cleanly.
    """
    pairs = Counter(
        (a[field], labels[a["alert_id"]].disposition.value) for a in alerts
    )
    by_value = defaultdict(set)
    for (value, disposition), _ in pairs.items():
        by_value[value].add(disposition)

    mixed = [v for v, outcomes in by_value.items() if len(outcomes) > 1]
    assert mixed, (
        f"every {field} value maps to exactly one disposition: "
        f"{ {v: sorted(o) for v, o in by_value.items()} }"
    )


def test_some_malicious_activity_is_under_rated(alerts, labels):
    """Real intrusions hide behind low-severity detections."""
    low_and_malicious = [
        a for a in alerts
        if a["severity"] in ("Low", "Informational")
        and labels[a["alert_id"]].disposition.value == "escalate"
    ]
    assert low_and_malicious, (
        "no malicious alert fires at low severity; the corpus cannot test "
        "whether the agent catches under-rated detections"
    )


def test_some_benign_activity_is_over_rated(alerts, labels):
    """High-severity false positives are the ones that burn analysts."""
    loud_and_benign = [
        a for a in alerts
        if a["severity"] in ("High", "Medium")
        and labels[a["alert_id"]].disposition.value == "close_benign"
    ]
    assert loud_and_benign, (
        "no benign alert fires at medium or high severity; the corpus cannot "
        "test whether the agent resists escalating on severity alone"
    )
