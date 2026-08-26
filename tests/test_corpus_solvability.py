"""Solvability invariants.

An alert is only a test case if the evidence needed to disposition it is
actually retrievable. Otherwise the model is guessing, and accuracy measures
luck while looking like reasoning.

Several corpus rationales assert enrichment facts: that a host is the
authorized scanner, that a service account should never log on interactively,
that an address has no intel on file. Those were promises when the templates
were written. This file turns them into checks.

The strongest cases here are the matched pairs. T1046 malicious and T1046
benign are the same detection with the same rule name; only asset context
separates them. If that context were unavailable, the pair would be
indistinguishable and the false-positive rate would be noise.
"""

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

from soc_triage.enrichment.base import EnrichmentStatus  # noqa: E402
from soc_triage.enrichment.stubs import LocalEnrichment  # noqa: E402
from soc_triage.environment import AccountType, Reputation  # noqa: E402
from soc_triage.evaluation.labels import CorpusSlice, load_labels  # noqa: E402

ALERTS_PATH = REPO_ROOT / "data" / "alerts.json"
LABELS_PATH = REPO_ROOT / "data" / "labels.json"


@pytest.fixture(scope="module")
def alerts() -> list[dict]:
    return json.loads(ALERTS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def labels():
    return load_labels(LABELS_PATH)


@pytest.fixture(scope="module")
def enrichment(alerts):
    return LocalEnrichment(alerts)


def _hostnames(event: dict) -> list[str]:
    return [event[k] for k in ("DvcHostname", "SrcHostname", "DstHostname")
            if event.get(k)]


def _usernames(event: dict) -> list[str]:
    return [event[k] for k in ("TargetUsername", "ActorUsername", "SrcUsername")
            if event.get(k)]


def _external_ips(event: dict) -> list[str]:
    return [event[k] for k in ("SrcIpAddr", "DstIpAddr")
            if event.get(k) and not str(event[k]).startswith(("10.", "192.168.", "172.16."))]


def _by_technique(alerts, labels, technique_id, slice_):
    return [a for a in alerts
            if a["technique_id"] == technique_id
            and labels[a["alert_id"]].corpus_slice is slice_]


def test_every_alert_has_at_least_one_resolvable_entity(alerts, enrichment):
    """No alert may be a total enrichment miss.

    An alert whose host, user, and addresses are all unknown gives the agent
    nothing beyond the raw record, and its disposition would be a guess.
    """
    orphans = []
    for alert in alerts:
        event = alert["event"]
        resolved = any(
            enrichment.asset(h).status is EnrichmentStatus.FOUND for h in _hostnames(event)
        ) or any(
            enrichment.identity(u).status is EnrichmentStatus.FOUND for u in _usernames(event)
        )
        if not resolved:
            orphans.append(f"{alert['alert_id']} ({alert['technique_id']})")
    assert not orphans, "alerts with no resolvable entity: " + ", ".join(orphans)


def test_t1046_pair_is_separable_only_by_asset_context(alerts, labels, enrichment):
    """The matched pair that proves false-positive rate means something."""
    malicious = _by_technique(alerts, labels, "T1046", CorpusSlice.MALICIOUS)
    benign = _by_technique(alerts, labels, "T1046", CorpusSlice.BENIGN)
    assert malicious and benign

    # Same detection fired on both sides.
    mal_rules = {a["event"]["NetworkRuleName"] for a in malicious}
    ben_rules = {a["event"]["NetworkRuleName"] for a in benign}
    assert mal_rules & ben_rules, (
        "benign and malicious T1046 use different rule names; the pair no longer "
        "tests whether the agent reasons past the signature"
    )

    for alert in benign:
        host = alert["event"]["SrcHostname"]
        result = enrichment.asset(host)
        assert result.status is EnrichmentStatus.FOUND, f"{alert['alert_id']}: {host} unknown"
        assert result.data.is_authorized_scanner, (
            f"{alert['alert_id']}: {host} is not tagged as an authorized scanner, "
            "so this benign alert is indistinguishable from the malicious variant"
        )

    for alert in malicious:
        host = alert["event"]["SrcHostname"]
        result = enrichment.asset(host)
        assert result.status is EnrichmentStatus.FOUND
        assert not result.data.is_authorized_scanner, (
            f"{alert['alert_id']}: {host} IS tagged as a scanner, which would make "
            "the correct disposition close rather than escalate"
        )


def test_t1078_malicious_identity_context_is_retrievable(alerts, labels, enrichment):
    """The service-account note is what makes this alert resolvable."""
    for alert in _by_technique(alerts, labels, "T1078", CorpusSlice.MALICIOUS):
        username = alert["event"]["TargetUsername"]
        result = enrichment.identity(username)
        assert result.status is EnrichmentStatus.FOUND, f"{username} unknown to the directory"
        assert result.data.account_type is AccountType.SERVICE, (
            f"{alert['alert_id']}: {username} is not a service account; the rationale "
            "depends on it being one"
        )
        assert "interactiv" in result.data.note.lower(), (
            f"{alert['alert_id']}: the directory note does not mention interactive logon, "
            "so the incriminating fact is not retrievable"
        )


def test_t1053_005_benign_deployment_context_is_retrievable(alerts, labels, enrichment):
    for alert in _by_technique(alerts, labels, "T1053.005", CorpusSlice.BENIGN):
        username = alert["event"]["ActorUsername"]
        result = enrichment.identity(username)
        assert result.status is EnrichmentStatus.FOUND
        assert result.data.account_type is AccountType.SERVICE
        assert "scheduled task" in result.data.note.lower(), (
            f"{alert['alert_id']}: nothing in the directory says this account creates "
            "scheduled tasks, so the exonerating fact is unavailable"
        )


def test_t1087_002_benign_host_is_tagged_for_directory_work(alerts, labels, enrichment):
    for alert in _by_technique(alerts, labels, "T1087.002", CorpusSlice.BENIGN):
        host = alert["event"]["DvcHostname"]
        result = enrichment.asset(host)
        assert result.status is EnrichmentStatus.FOUND
        assert "directory-tools" in result.data.tags, (
            f"{alert['alert_id']}: {host} carries no directory-tools tag"
        )


def test_abstention_cases_really_have_thin_evidence(alerts, labels, enrichment):
    """Alerts marked abstention-acceptable must have an unresolved source.

    If intel returned a clean or malicious verdict, the evidence would be
    sufficient and abstaining would be a cop-out rather than a defensible
    call. The label would be wrong.
    """
    by_id = {a["alert_id"]: a for a in alerts}
    thin = [l for l in labels.values() if l.abstention_acceptable]
    assert thin, "no thin-evidence alerts; the abstention metric is vacuous"

    for label in thin:
        event = by_id[label.alert_id]["event"]
        ips = _external_ips(event)
        assert ips, f"{label.alert_id}: no external address to be uncertain about"
        verdicts = {enrichment.reputation(ip).data.reputation for ip in ips
                    if enrichment.reputation(ip).data is not None}
        assert Reputation.UNKNOWN in verdicts, (
            f"{label.alert_id}: intel returns {verdicts}, which is not thin evidence"
        )


def test_malicious_external_sources_have_intel(alerts, labels, enrichment):
    """Where a malicious alert leans on source reputation, intel must answer."""
    for alert in alerts:
        label = labels[alert["alert_id"]]
        if label.corpus_slice is not CorpusSlice.MALICIOUS:
            continue
        if "reputation" not in label.rationale and "intel" not in label.rationale:
            continue
        ips = _external_ips(alert["event"])
        assert ips, f"{alert['alert_id']}: rationale cites reputation but no external IP"
        verdicts = [enrichment.reputation(ip).data for ip in ips]
        assert any(v is not None and v.reputation in
                   (Reputation.MALICIOUS, Reputation.SUSPICIOUS) for v in verdicts), (
            f"{alert['alert_id']}: rationale cites threat intel, but no source address "
            "returns a malicious or suspicious verdict"
        )


def test_internal_addresses_are_not_given_fabricated_verdicts(enrichment):
    """Asking external intel about RFC1918 space must not invent an answer."""
    for ip in ("10.14.22.87", "192.168.1.10", "172.16.4.4"):
        result = enrichment.reputation(ip)
        assert result.status is EnrichmentStatus.NOT_FOUND
        assert result.data is None, f"{ip}: fabricated an external reputation"


def test_correlation_finds_the_multi_stage_cases(alerts, enrichment):
    """At least some alerts share a host within a working window.

    Correlation is one of the four enrichment lookups. If no alert ever had a
    neighbour, the capability would be untested by the corpus.
    """
    with_neighbours = 0
    for alert in alerts:
        host = alert["event"].get("DvcHostname")
        if not host:
            continue
        result = enrichment.related(
            alert_id=alert["alert_id"], hostname=host, window_minutes=1440
        )
        if result.data and result.data.count:
            with_neighbours += 1
    assert with_neighbours >= 10, (
        f"only {with_neighbours} alerts have same-host neighbours within 24h; "
        "correlation is effectively untested"
    )
