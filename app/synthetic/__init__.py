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
"""Synthetic load mode: scan a generated organization instead of Google Cloud.

Why: there is no test organization with thousands of projects, but the
architecture has to be validated at that size (hung scans, container crashes
and API rate limits were the reasons for the beta fan-out). This mode keeps the
whole application unchanged (routes, Cloud Tasks, GCS results, the checks, the
reports) and swaps only the data plane, through the provider seam in
``app.services.gcp``:

- :mod:`app.synthetic.world` generates the organization deterministically from
  ``(seed, project index)``.
- :mod:`app.synthetic.provider` answers every data-plane API from that world,
  with simulated latency, optional 429s, denied projects, and call metrics.
- :mod:`app.synthetic.memory_store` is an in-memory results bucket for the
  offline harness (``tools/synthetic_scan.py``) and the tests.

Two ways to use it:

1. **Offline harness** (no Google Cloud at all): ``python tools/synthetic_scan.py
   --projects 500``. Runs a scan in-process, prints API-call and timing metrics,
   writes the reports to a local directory.
2. **Deployed synthetic revision**: deploy the normal image with
   ``CLOUDGAUGE_ENV=synthetic`` and ``SYNTHETIC_PROJECTS=<n>``. Cloud Run,
   Cloud Tasks and the results bucket are real, so the end-to-end behaviour
   (task deadlines, memory, timeouts, status polling) is what production would
   do with an organization of that size. Every report carries a banner saying
   its data is synthetic.

Opting in needs both the profile and ``SYNTHETIC_PROJECTS``; the settings
reject one without the other (see ``app.config``).
"""
import logging

from app.services import gcp
from app.synthetic.provider import CallMetrics, SyntheticGcp
from app.synthetic.world import SyntheticOrg

__all__ = ["CallMetrics", "SyntheticGcp", "SyntheticOrg", "build_provider", "install", "banner_for"]


def build_provider(settings):
    """A :class:`SyntheticGcp` configured from the ``SYNTHETIC_*`` settings."""
    return SyntheticGcp(
        settings.synthetic_projects,
        seed=settings.synthetic_seed,
        latency_ms=settings.synthetic_latency_ms,
        error_rate=settings.synthetic_error_rate,
        denied_fraction=settings.synthetic_denied_fraction,
    )


def banner_for(provider):
    """The notice shown on every page and report produced in synthetic mode."""
    about = provider.describe()
    return (f"SYNTHETIC LOAD TEST \u2014 generated organization of {about['projects']:,} projects "
            f"(seed {about['seed']}, median API latency {about['latency_ms']:g} ms). "
            "Nothing in this report is real Google Cloud data.")


def install(settings):
    """Builds the provider for ``settings``, installs it in ``app.services.gcp`` and returns it."""
    provider = build_provider(settings)
    gcp.install_provider(provider)
    logging.warning(f"SYNTHETIC LOAD MODE: data-plane APIs are simulated ({provider.describe()}); "
                    "Cloud Tasks and the results bucket are real.")
    return provider
