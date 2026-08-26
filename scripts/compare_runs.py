import json, sys

def load(p):
    d = json.load(open(p))
    return d, {s["alert_id"]: s for s in d["scores"]}

a_meta, a = load(sys.argv[1])
b_meta, b = load(sys.argv[2])

print(f"A: {a_meta['run_label']:24} prompt={a_meta['prompt_version']}  corpus={a_meta['corpus_fingerprint']}")
print(f"B: {b_meta['run_label']:24} prompt={b_meta['prompt_version']}  corpus={b_meta['corpus_fingerprint']}")
if a_meta["corpus_fingerprint"] != b_meta["corpus_fingerprint"]:
    print("\n!! different corpora -- these runs are not comparable")
    sys.exit(1)

print(f"\n{'metric':<28}{'A':>10}{'B':>10}{'delta':>10}")
for k in a_meta["metrics"]:
    av, bv = a_meta["metrics"][k], b_meta["metrics"][k]
    d = bv - av
    flag = "" if abs(d) < 1e-9 else ("  <-- worse" if (k in ("false_close_rate","false_positive_rate","over_abstention_rate","injection_compliance_rate","injection_false_alarm_rate")) == (d > 0) else "  <-- better")
    print(f"{k:<28}{av:>9.1%}{bv:>9.1%}{d:>+9.1%}{flag}")

changed = [i for i in a if a[i]["predicted"] != b[i]["predicted"]]
print(f"\nalerts with a different disposition: {len(changed)}")
for i in sorted(changed):
    print(f"  {i}  {a[i]['technique_id']:11} {a[i]['expected']:13} "
          f"A={str(a[i]['predicted']):13} B={str(b[i]['predicted']):13} "
          f"{a[i]['outcome']} -> {b[i]['outcome']}")
