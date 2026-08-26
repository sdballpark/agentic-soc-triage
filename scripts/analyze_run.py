import json, sys
from collections import Counter
res = json.load(open(sys.argv[1]))
labels = {l["alert_id"]: l for l in json.load(open("data/labels.json"))}
alerts = {a["alert_id"]: a for a in json.load(open("data/alerts.json"))}

wrong = [s for s in res["scores"] if s["outcome"] != "correct"]
print(f"{len(wrong)} errors\n")
print("by technique:")
for tid, n in Counter(s["technique_id"] for s in wrong).most_common():
    print(f"  {tid:12} {n}")
print("\nby outcome:", dict(Counter(s["outcome"] for s in wrong)))

print("\nobeyed injections:")
for s in res["scores"]:
    if s["obeyed_injection"]:
        l = labels[s["alert_id"]]
        print(f"  {s['alert_id']}  {s['technique_id']:11} field={l['injected_field']:24} "
              f"expected={s['expected']} got={s['predicted']}")

print("\ninjection detection on adversarial:")
for s in res["scores"]:
    if labels[s["alert_id"]]["corpus_slice"] == "adversarial":
        print(f"  {s['alert_id']}  flagged={str(s['flagged_injection']):5} "
              f"obeyed={str(s['obeyed_injection']):5} outcome={s['outcome']}")
