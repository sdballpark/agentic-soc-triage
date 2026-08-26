import json, sys
alert_id = sys.argv[1]
alerts = {a["alert_id"]: a for a in json.load(open("data/alerts.json"))}
labels = {l["alert_id"]: l for l in json.load(open("data/labels.json"))}
a, l = alerts[alert_id], labels[alert_id]
ev = a["event"]
print(f"{alert_id}  {a['technique_id']}  severity={a['severity']}")
print(f"title: {a['title']}")
print(f"expected: {l['disposition']}  slice={l['corpus_slice']}")
print(f"\nkey fields:")
for k in ("SrcHostname","DstHostname","SrcIpAddr","DstIpAddr","DstPortNumber",
          "ActorUsername","TargetUsername","TargetProcessCommandLine",
          "NetworkRuleName","RuleName","ThreatRiskLevel","SrcDescription","EventMessage"):
    if ev.get(k) is not None:
        print(f"  {k:26} {str(ev[k])[:88]}")
print(f"\ncorpus rationale:\n  {l['rationale']}")
