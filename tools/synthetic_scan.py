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

With ``--shard-size`` the job runs the way the deployed service runs scopes
with more projects than one shard holds (``app.fanout``): the dispatcher plans
the shards, an in-process queue plays Cloud Tasks (named tasks created once,
``--concurrency`` deliveries at a time, retries on failure), the shards run
their checks, the last one triggers the aggregation, and the sweeper finds the
job complete. The summary then adds the dispatch time, the median and longest
shard, retries, the aggregation time, and the report's coverage line.

Examples::

    python tools/synthetic_scan.py --projects 100
    python tools/synthetic_scan.py --projects 1000 --latency-ms 150 --json results.json
    python tools/synthetic_scan.py --projects 50 --latency-ms 0 --error-rate 0.02 --scope folder
    python tools/synthetic_scan.py --projects 1000 --shard-size 20 --concurrency 25 --latency-ms 0

``--latency-ms 0`` measures pure CPU and call counts in seconds; the default
150 ms median approximates real API latency, so a run with 1,000 projects
takes as long as the real thing would. Results are deterministic for a given
``--seed`` (the data; latency and injected errors are random but seeded).

Not part of the deployed image (see .dockerignore). Run from the repository
root with the project's virtualenv active.
"""
import argparse
import collections
import json
import os
import platform
import re
import resource
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from html import unescape

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import scan_job  # noqa: E402
from app.config import (  # noqa: E402
    DEFAULT_SCAN_MAX_CONCURRENT_SHARDS, DEFAULT_SHARD_TIME_BUDGET_SECONDS, DEFAULT_SYNTHETIC_DENIED_FRACTION,
    DEFAULT_SYNTHETIC_ERROR_RATE, DEFAULT_SYNTHETIC_LATENCY_MS, DEFAULT_SYNTHETIC_SEED, QUEUE_MAX_ATTEMPTS, Settings,
)
from app.fanout import AGGREGATE_PATH, SHARD_PATH, FanOut  # noqa: E402
from app.services import gcp  # noqa: E402
from app.synthetic import SyntheticGcp, banner_for  # noqa: E402
from app.synthetic.memory_store import memory_results_store  # noqa: E402
from app.utils import configure_logging  # noqa: E402

# One pair per check item: the title and the status pill in its accordion's summary row.
CHECK_STATUS = re.compile(r'<span class="check-title"><strong>([^<]+)</strong>.*?<span class="status-badge[^"]*">([^<]+)</span>', re.S)
COVERAGE_LINE = re.compile(r'<dt>Coverage</dt><dd class="coverage[^"]*"><span class="dot dot-[\w-]+"></span>(.*?)</dd>', re.S)


def peak_rss_mb():
    """Peak resident set size of this process, in MiB (macOS reports bytes, Linux KiB)."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / (1024 * 1024 if platform.system() == "Darwin" else 1024), 1)


def coverage_text(html):
    """The header's Coverage line as plain text, or ``None`` when the scan could not count its projects."""
    match = COVERAGE_LINE.search(html)
    if not match:
        return None
    return " ".join(unescape(match.group(1)).split())


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--projects", type=int, required=True, help="number of generated projects")
    parser.add_argument("--scope", choices=("organization", "folder", "project"), default="organization",
                        help="scan scope (default: organization; folder scans the first folder, project the first project)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SYNTHETIC_SEED, help="seed for the generated organization")
    parser.add_argument("--latency-ms", type=float, default=DEFAULT_SYNTHETIC_LATENCY_MS, help="median simulated latency per API call")
    parser.add_argument("--error-rate", type=float, default=DEFAULT_SYNTHETIC_ERROR_RATE, help="share of API calls that fail with 429")
    parser.add_argument("--denied-fraction", type=float, default=DEFAULT_SYNTHETIC_DENIED_FRACTION, help="share of projects that answer 403")
    sharding = parser.add_argument_group("sharded scan (the deployed service's path above SCAN_SHARD_SIZE projects)")
    sharding.add_argument("--shard-size", type=int, default=0, metavar="N",
                          help="run the job in shards of N projects (default: 0, one task like a small scope)")
    sharding.add_argument("--concurrency", type=int, default=DEFAULT_SCAN_MAX_CONCURRENT_SHARDS,
                          help="shards delivered at a time, like the queue's max concurrent dispatches (default: %(default)s)")
    sharding.add_argument("--shard-budget-seconds", type=int, default=DEFAULT_SHARD_TIME_BUDGET_SECONDS,
                          help="a shard's time budget for its checks (default: %(default)s)")
    sharding.add_argument("--max-attempts", type=int, default=QUEUE_MAX_ATTEMPTS,
                          help="attempts per task before a shard becomes error rows (default: %(default)s)")
    parser.add_argument("--output-dir", default="synthetic-reports", help="where to write the HTML and CSV reports")
    parser.add_argument("--json", help="also write the metrics to this JSON file")
    parser.add_argument("--quiet", action="store_true", help="hide the scan's own log output")
    args = parser.parse_args(argv)
    if args.shard_size < 0 or args.concurrency < 1 or args.max_attempts < 1:
        parser.error("--shard-size must be 0 or more; --concurrency and --max-attempts at least 1")
    return args


class LocalQueue:
    """Plays Cloud Tasks in-process for ``FanOut``: named tasks, concurrent delivery, retries on failure."""

    def __init__(self, concurrency, max_attempts):
        self.concurrency, self.max_attempts = concurrency, max_attempts
        self.lock = threading.Lock()
        self.names, self.done = set(), set()
        self.pending = collections.deque()  # (path, body, task_id, retry_count)
        self.scheduled = collections.deque()  # (path, body, task_id): tasks due later (the sweeps)
        self.deliveries = []  # one dict per delivery, in completion order

    def enqueue(self, path, body, task_id, schedule_delay_seconds=None):
        with self.lock:
            if task_id in self.names:
                return False  # Cloud Tasks: AlreadyExists
            self.names.add(task_id)
            if schedule_delay_seconds:
                self.scheduled.append((path, body, task_id))
            else:
                self.pending.append((path, body, task_id, 0))
        return True

    def task_exists(self, task_id):
        with self.lock:
            return task_id in self.names and task_id not in self.done

    def deliver(self, fan, path, body, task_id, retry_count):
        started = time.monotonic()
        if path == SHARD_PATH:
            ok = fan.run_shard(body, retry_count)
        elif path == AGGREGATE_PATH:
            ok = fan.aggregate(body, retry_count)
        else:
            ok = fan.sweep(body)
        with self.lock:
            self.deliveries.append({"path": path, "shard_id": body.get("shard_id"), "sweep": body.get("sweep"),
                                    "attempt": retry_count + 1, "ok": ok, "seconds": round(time.monotonic() - started, 1)})
            if not ok and retry_count + 1 < self.max_attempts:
                self.pending.append((path, body, task_id, retry_count + 1))
            else:
                self.done.add(task_id)

    def drain(self, fan):
        """Delivers every pending task, and the tasks they create, ``concurrency`` at a time."""
        in_flight = set()
        with ThreadPoolExecutor(max_workers=self.concurrency, thread_name_prefix="task") as pool:
            while True:
                with self.lock:
                    while self.pending and len(in_flight) < self.concurrency:
                        in_flight.add(pool.submit(self.deliver, fan, *self.pending.popleft()))
                if not in_flight:
                    break
                finished, in_flight = wait(in_flight, return_when=FIRST_COMPLETED)
                for future in finished:
                    future.result()  # a bug in the harness itself: raise it
        # The sweeps, due later: deliver them now (they find the job complete, or finish it).
        while self.scheduled:
            path, body, task_id = self.scheduled.popleft()
            self.deliver(fan, path, body, task_id, 0)
            self.drain_pending_only(fan)

    def drain_pending_only(self, fan):
        while self.pending:
            self.deliver(fan, *self.pending.popleft())


def run_sharded(args, job, store, banner):
    """Runs ``job`` as a sharded scan: dispatcher, shards, fan-in, aggregation, sweep. Returns the metrics."""
    settings = Settings(scan_shard_size=args.shard_size, scan_max_concurrent_shards=args.concurrency,
                        shard_time_budget_seconds=args.shard_budget_seconds, task_max_attempts=args.max_attempts)
    queue = LocalQueue(args.concurrency, args.max_attempts)
    fan = FanOut(settings, store, enqueue=queue.enqueue, task_exists=queue.task_exists, banner=banner)
    started = time.monotonic()
    ok = scan_job.execute_scan_job(job, store=store, banner=banner, fanout=fan)
    dispatch_seconds = time.monotonic() - started
    queue.drain(fan)

    shard_runs = [d for d in queue.deliveries if d["path"] == SHARD_PATH]
    aggregations = [d for d in queue.deliveries if d["path"] == AGGREGATE_PATH]
    times = sorted(d["seconds"] for d in shard_runs if d["ok"])
    return {
        "ok": ok and bool(aggregations) and aggregations[-1]["ok"],
        "shard_size": args.shard_size, "concurrency": args.concurrency, "max_attempts": args.max_attempts,
        "dispatch_seconds": round(dispatch_seconds, 1),
        "shards": len({d["shard_id"] for d in shard_runs}),
        "shard_attempts": len(shard_runs), "shard_retries": sum(1 for d in shard_runs if d["attempt"] > 1),
        "failed_shards": sum(1 for d in shard_runs if not d["ok"] and d["attempt"] == args.max_attempts),
        "median_shard_seconds": times[len(times) // 2] if times else None,
        "longest_shard_seconds": times[-1] if times else None,
        "aggregation_attempts": len(aggregations),
        "aggregation_seconds": aggregations[-1]["seconds"] if aggregations else None,
        "sweeps": sum(1 for d in queue.deliveries if d["sweep"]),
        "deliveries": queue.deliveries,
    }


def run(args):
    provider = SyntheticGcp(args.projects, seed=args.seed, latency_ms=args.latency_ms,
                            error_rate=args.error_rate, denied_fraction=args.denied_fraction)
    gcp.install_provider(provider)
    store = memory_results_store()
    world = provider.world
    scope_id = {"organization": world.org_id, "folder": world.folder_ids[0], "project": world.project_id(0)}[args.scope]
    job_id = f"synthetic-{args.scope}-{args.projects}-{int(time.time())}"
    job = {"scope": args.scope, "scope_id": scope_id, "job_id": job_id}

    print(f"Synthetic scan: {args.scope} {scope_id}, {args.projects} projects, seed {args.seed}, "
          f"latency {args.latency_ms:g} ms, error rate {args.error_rate:g}, denied {args.denied_fraction:g}"
          + (f", shards of {args.shard_size} ({args.concurrency} at a time)" if args.shard_size else ""))
    print(f"Organization: {world.summary()}")
    started = time.monotonic()
    sharding = None
    if args.shard_size:
        sharding = run_sharded(args, job, store, banner_for(provider))
        ok = sharding.pop("ok")
    else:
        ok = scan_job.execute_scan_job(job, store=store, banner=banner_for(provider))
    elapsed = time.monotonic() - started

    html = store.read_report(job_id, scope_id, "html") or ""
    csv = store.read_report(job_id, scope_id, "csv") or ""
    status = store.read_status(job_id, scope_id) or {}
    checks = CHECK_STATUS.findall(html)
    metrics = provider.metrics.snapshot()
    result = {
        "run": {"scope": args.scope, "scope_id": scope_id, "projects": args.projects, "seed": args.seed,
                "latency_ms": args.latency_ms, "error_rate": args.error_rate, "denied_fraction": args.denied_fraction,
                "shard_size": args.shard_size, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")},
        "outcome": {"ok": ok, "status": status.get("status"), "final_task": status.get("current_task"),
                    "elapsed_seconds": round(elapsed, 1), "peak_rss_mb": peak_rss_mb()},
        "api": metrics,
        "api_calls_per_project": round(metrics["total_calls"] / max(1, args.projects), 1),
        "results_bucket": store.client.stats(),
        "report": {"html_bytes": len(html), "csv_bytes": len(csv), "csv_lines": csv.count("\n"),
                   "checks": len(checks), "by_status": {}, "error_checks": [], "coverage": coverage_text(html)},
    }
    if sharding is not None:
        result["sharding"] = sharding
    for name, check_status in checks:
        result["report"]["by_status"][check_status] = result["report"]["by_status"].get(check_status, 0) + 1
        if check_status == "Error":
            result["report"]["error_checks"].append(name)

    os.makedirs(args.output_dir, exist_ok=True)
    base = os.path.join(args.output_dir, f"{args.scope}-{args.projects}-seed{args.seed}" + (f"-shards{args.shard_size}" if args.shard_size else ""))
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
    sharding = result.get("sharding")
    if sharding:
        print(f"Sharded: {sharding['shards']} shards of {sharding['shard_size']}, {sharding['concurrency']} at a time: "
              f"dispatch {sharding['dispatch_seconds']}s, shards median {sharding['median_shard_seconds']}s / "
              f"longest {sharding['longest_shard_seconds']}s, {sharding['shard_retries']} retries, "
              f"{sharding['failed_shards']} failed for good, aggregation {sharding['aggregation_seconds']}s "
              f"({sharding['aggregation_attempts']} attempt(s)), {sharding['sweeps']} sweep(s)")
        print("  (peak RSS is this one process running every concurrent shard; in Cloud Run each shard is its own request)")
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
    if report.get("coverage"):
        print(f"  coverage: {report['coverage']}")
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
