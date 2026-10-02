# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Offline load test: scan a generated organization in-process, without Google Cloud.

Runs the real scan job (``app.scan_job.execute_scan_job``: discovery, every
check on the thread pool, findings, HTML and CSV reports) against the synthetic
provider and an in-memory results bucket, then prints what the architecture
work needs to know for an organization of that size:

- how many API calls a scan makes, per API and per method (quota pressure),
- wall-clock time, the simulated time spent waiting on APIs, and the peak
  number of concurrent in-flight calls (how much the thread pool really
  parallelizes),
- peak memory of the process (does one container survive the scan?),
- how many objects the scan writes to the results bucket and the report sizes,
- which checks ended in an error state.

Examples::

    python tools/synthetic_scan.py --projects 100
    python tools/synthetic_scan.py --projects 1000 --latency-ms 150 --json results.json
    python tools/synthetic_scan.py --projects 50 --latency-ms 0 --error-rate 0.02 --scope folder

``--latency-ms 0`` measures pure CPU and call counts in seconds; the default
150 ms median approximates real API latency, so a run with 1,000 projects
takes as long as the real thing would. Results are deterministic for a given
``--seed`` (the data; latency and injected errors are random but seeded).

Not part of the deployed image (see .dockerignore). Run from the repository
root with the project's virtualenv active.
"""
import argparse
import json
import os
import platform
import re
import resource
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import scan_job  # noqa: E402
from app.config import (  # noqa: E402
    DEFAULT_SYNTHETIC_DENIED_FRACTION, DEFAULT_SYNTHETIC_ERROR_RATE, DEFAULT_SYNTHETIC_LATENCY_MS, DEFAULT_SYNTHETIC_SEED,
)
from app.services import gcp  # noqa: E402
from app.synthetic import SyntheticGcp, banner_for  # noqa: E402
from app.synthetic.memory_store import memory_results_store  # noqa: E402
from app.utils import configure_logging  # noqa: E402

CHECK_STATUS = re.compile(r'<strong>([^<]+)</strong>.*?<span class="status-badge">([^<]+)</span>', re.S)


def peak_rss_mb():
    """Peak resident set size of this process, in MiB (macOS reports bytes, Linux KiB)."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / (1024 * 1024 if platform.system() == "Darwin" else 1024), 1)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--projects", type=int, required=True, help="number of generated projects")
    parser.add_argument("--scope", choices=("organization", "folder", "project"), default="organization",
                        help="scan scope (default: organization; folder scans the first folder, project the first project)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SYNTHETIC_SEED, help="seed for the generated organization")
    parser.add_argument("--latency-ms", type=float, default=DEFAULT_SYNTHETIC_LATENCY_MS, help="median simulated latency per API call")
    parser.add_argument("--error-rate", type=float, default=DEFAULT_SYNTHETIC_ERROR_RATE, help="share of API calls that fail with 429")
    parser.add_argument("--denied-fraction", type=float, default=DEFAULT_SYNTHETIC_DENIED_FRACTION, help="share of projects that answer 403")
    parser.add_argument("--output-dir", default="synthetic-reports", help="where to write the HTML and CSV reports")
    parser.add_argument("--json", help="also write the metrics to this JSON file")
    parser.add_argument("--quiet", action="store_true", help="hide the scan's own log output")
    return parser.parse_args(argv)


def run(args):
    provider = SyntheticGcp(args.projects, seed=args.seed, latency_ms=args.latency_ms,
                            error_rate=args.error_rate, denied_fraction=args.denied_fraction)
    gcp.install_provider(provider)
    store = memory_results_store()
    world = provider.world
    scope_id = {"organization": world.org_id, "folder": world.folder_ids[0], "project": world.project_id(0)}[args.scope]
    job_id = f"synthetic-{args.scope}-{args.projects}-{int(time.time())}"

    print(f"Synthetic scan: {args.scope} {scope_id}, {args.projects} projects, seed {args.seed}, "
          f"latency {args.latency_ms:g} ms, error rate {args.error_rate:g}, denied {args.denied_fraction:g}")
    print(f"Organization: {world.summary()}")
    started = time.monotonic()
    ok = scan_job.execute_scan_job({"scope": args.scope, "scope_id": scope_id, "job_id": job_id},
                                   store=store, banner=banner_for(provider))
    elapsed = time.monotonic() - started

    html = store.read_report(job_id, scope_id, "html") or ""
    csv = store.read_report(job_id, scope_id, "csv") or ""
    status = store.read_status(job_id, scope_id) or {}
    checks = CHECK_STATUS.findall(html)
    metrics = provider.metrics.snapshot()
    result = {
        "run": {"scope": args.scope, "scope_id": scope_id, "projects": args.projects, "seed": args.seed,
                "latency_ms": args.latency_ms, "error_rate": args.error_rate, "denied_fraction": args.denied_fraction,
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds")},
        "outcome": {"ok": ok, "status": status.get("status"), "final_task": status.get("current_task"),
                    "elapsed_seconds": round(elapsed, 1), "peak_rss_mb": peak_rss_mb()},
        "api": metrics,
        "api_calls_per_project": round(metrics["total_calls"] / max(1, args.projects), 1),
        "results_bucket": store.client.stats(),
        "report": {"html_bytes": len(html), "csv_bytes": len(csv), "csv_lines": csv.count("\n"),
                   "checks": len(checks), "by_status": {}, "error_checks": []},
    }
    for name, check_status in checks:
        result["report"]["by_status"][check_status] = result["report"]["by_status"].get(check_status, 0) + 1
        if check_status == "Error":
            result["report"]["error_checks"].append(name)

    os.makedirs(args.output_dir, exist_ok=True)
    base = os.path.join(args.output_dir, f"{args.scope}-{args.projects}-seed{args.seed}")
    with open(base + ".html", "w", encoding="utf-8") as f:
        f.write(html)
    with open(base + ".csv", "w", encoding="utf-8") as f:
        f.write(csv)
    result["report"]["files"] = [base + ".html", base + ".csv"]
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    return result


def print_summary(result):
    outcome, api, report = result["outcome"], result["api"], result["report"]
    print("\n" + "=" * 72)
    print(f"RESULT: {'ok' if outcome['ok'] else 'FAILED'} (status={outcome['status']}) in {outcome['elapsed_seconds']}s, "
          f"peak RSS {outcome['peak_rss_mb']} MiB")
    print(f"API calls: {api['total_calls']:,} ({result['api_calls_per_project']} per project), "
          f"simulated wait {api['simulated_wait_seconds']:,}s, max in flight {api['max_in_flight']}")
    print("  by API:    " + ", ".join(f"{k} {v:,}" for k, v in api["by_api"].items()))
    top = list(api["by_method"].items())[:8]
    print("  top calls: " + ", ".join(f"{k} {v:,}" for k, v in top))
    if api["errors"]:
        print("  errors:    " + ", ".join(f"{k} {v:,}" for k, v in api["errors"].items()))
    print(f"Results bucket: {result['results_bucket']}")
    print(f"Report: {report['html_bytes'] / 1024:,.0f} KiB HTML, {report['csv_bytes'] / 1024:,.0f} KiB CSV "
          f"({report['csv_lines']:,} lines), {report['checks']} checks: {report['by_status']}")
    if report["error_checks"]:
        print(f"  checks in error: {report['error_checks']}")
    print(f"  files: {report['files']}")
    print("=" * 72)


def main(argv=None):
    args = parse_args(argv)
    if args.quiet:
        import logging

        previous_stdout = sys.stdout
        logging.disable(logging.CRITICAL)  # the checks log every denied project at ERROR
        sys.stdout = open(os.devnull, "w")
        try:
            result = run(args)
        finally:
            sys.stdout.close()
            sys.stdout = previous_stdout
            logging.disable(logging.NOTSET)
    else:
        configure_logging()
        result = run(args)
    print_summary(result)
    return 0 if result["outcome"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
