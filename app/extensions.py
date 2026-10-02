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
"""The per-app service container, stored at ``app.extensions["cloudgauge"]``.

Route handlers get their dependencies from ``get_services()`` instead of module
globals, so every app instance (and every test) can have its own. Nothing here
creates a GCP client until it is first needed.
"""
import threading
from dataclasses import dataclass, field

from flask import current_app

from app.config import Settings
from app.services import gcp, tasks
from app.services.results_store import GcsResultsStore
from app.services.worker_url import resolve_worker_url

EXTENSION_KEY = "cloudgauge"


@dataclass
class Services:
    """Dependencies of the route handlers.

    Attributes:
        settings: The app's settings.
        results_store: Findings, status, and reports (``GcsResultsStore`` or a fake).
        tasks_client: Cloud Tasks client; ``None`` means the process-wide shared client.
        worker_url: URL that Cloud Tasks calls; ``None`` means resolve it on first use.
        report_banner: Notice rendered on the pages and reports; ``None`` means none.
            The synthetic load mode sets it so no synthetic report can pass for a real one.
        fanout: The sharded-scan orchestrator (``app.fanout.FanOut``); ``None`` means
            build it on first use from the fields above.
    """
    settings: Settings
    results_store: GcsResultsStore
    tasks_client: object = None
    worker_url: str | None = None
    report_banner: str | None = None
    fanout: object = None
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False, compare=False)

    def get_tasks_client(self):
        """Returns the injected Cloud Tasks client, or the shared one (created on first use)."""
        if self.tasks_client is None:
            self.tasks_client = gcp.tasks_client()
        return self.tasks_client

    def get_worker_url(self):
        """Returns the worker URL, resolving it once: ``WORKER_URL``, else Cloud Run self-discovery."""
        if self.worker_url is None:
            with self._lock:
                if self.worker_url is None:
                    self.worker_url = resolve_worker_url(self.settings)
        return self.worker_url

    def enqueue_task(self, path, body, task_id, schedule_delay_seconds=None):
        """Creates the named task ``task_id`` calling ``path`` on this service; ``False`` if it already exists."""
        return tasks.enqueue_task(self.settings, self.get_worker_url(), path, body, task_id=task_id,
                                  schedule_delay_seconds=schedule_delay_seconds, client=self.get_tasks_client())

    def task_exists(self, task_id):
        """Whether the named task is still on the queue (``None`` if the lookup failed)."""
        return tasks.task_exists(self.settings, task_id, client=self.get_tasks_client())

    def get_fanout(self):
        """Returns the sharded-scan orchestrator, built on first use."""
        if self.fanout is None:
            from app.fanout import FanOut  # imports the checks and reporting; only needed by the worker routes

            with self._lock:
                if self.fanout is None:
                    self.fanout = FanOut(self.settings, self.results_store, enqueue=self.enqueue_task,
                                         task_exists=self.task_exists, banner=self.report_banner)
        return self.fanout


def build_services(settings):
    """Returns the production services for ``settings``; clients are created on first use.

    In the synthetic profile the data-plane provider is installed here too, so a
    ``Services`` built from synthetic settings always scans the generated
    organization and labels what it produces.
    """
    banner = None
    if settings.is_synthetic:
        from app import synthetic  # imports the checks; only needed in this profile

        banner = synthetic.banner_for(synthetic.install(settings))
    return Services(settings=settings, results_store=GcsResultsStore(settings.results_bucket), report_banner=banner)


def get_services():
    """Returns the current app's :class:`Services` (for use in request handlers)."""
    return current_app.extensions[EXTENSION_KEY]
