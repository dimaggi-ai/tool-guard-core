import json, math, statistics
from pathlib import Path
x = json.loads(Path(__file__).with_name("hosted-analysis.json").read_text())
v = [math.log(r["candidate_count"] / r["baseline_count"]) for r in x["runs"]]
assert len(v) == 20
# One-sided Student-t quantile for 19 degrees of freedom, probability 0.99.
t = 2.5394831906239625
lower = statistics.mean(v) - t * statistics.stdev(v) * math.sqrt(1 + 1 / len(v))
trigger = math.ceil(10000 * (1 - math.exp(lower))) / 100
assert trigger == 1.35
print(json.dumps({"n": len(v), "lower_log_bound": lower, "trigger_percent": trigger}))
