import hashlib, json, math, re, statistics, tarfile
from pathlib import Path
root = Path(__file__).parent
x = json.loads((root / "hosted-analysis.json").read_text())
assert len(x["runs"]) == len({r["run"] for r in x["runs"]}) == 20
with tarfile.open(root / "hosted-evidence.tar.gz") as archive:
    for r in x["runs"]:
        raw = archive.extractfile(r["run"] + ".log").read()
        assert hashlib.sha256(raw).hexdigest() == r["log_sha256"]
        counts = re.findall(rb"concurrency=50\s+total=\d+\s+success_contract=(\d+)", raw)
        assert list(map(int, counts[:2])) == [r["candidate_count"], r["baseline_count"]]
        metadata = json.load(archive.extractfile(r["run"] + ".json"))
        assert metadata["conclusion"] == "success" and metadata["headSha"] == x["candidate"]
        assert b"baseline=v0.8.1" in raw and b"go version go1.26.9 linux/amd64" in raw
v = [math.log(r["candidate_count"] / r["baseline_count"]) for r in x["runs"]]
assert math.isclose(statistics.mean(v), x["mean_log_ratio"], abs_tol=1e-12)
assert math.isclose(statistics.stdev(v), x["sd_log_ratio"], abs_tol=1e-12)
# One-sided Student-t quantiles for 19 degrees of freedom; recorded precision.
for level, t in [("0.95", 1.7291328115213682), ("0.99", 2.5394831906239625)]:
    lower = statistics.mean(v) - t * statistics.stdev(v) * math.sqrt(1 + 1 / len(v))
    loss = 100 * (1 - math.exp(lower))
    bound = x["prediction_bounds"][level]
    assert math.isclose(lower, bound["lower_log_prediction_bound"], abs_tol=1e-12)
    assert math.isclose(loss, bound["loss_prediction_bound_pct"], abs_tol=1e-10)
    assert math.ceil(loss * 100) / 100 == bound["conservative_ceil_0_01pp"]
print("Verified all 20 raw hosted logs, counts and both prediction bounds")
