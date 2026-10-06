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
"""CloudGauge application package.

Layout:

- ``app.config``      constants and environment-driven ``Settings``
- ``app.utils``       logging setup, API backoff, CSV helpers, progress throttling
- ``app.services``    GCP I/O: clients, results store, Cloud Tasks, discovery, Gemini
- ``app.checks``      the scan checks, their registry, and the concurrent runner
- ``app.reporting``   report view-model plus the HTML (Jinja) and CSV reports
- ``app.scan_job``    one scan job end to end (what ``/run-scan`` runs)
- ``app.extensions``  the per-app service container used by the routes
- ``app.routes``      blueprints: ``ui``, ``api`` (``/api``), ``worker``
- ``app/templates``   Jinja templates for the pages and the report

``create_app()`` is the application factory; ``cloudgauge.py`` calls it for gunicorn.

Design rule: importing this package or any submodule performs no I/O (no GCP
clients, no network calls, no env validation). Keep this file free of eager
submodule imports to avoid import cycles: ``create_app`` imports Flask and the
routes when it runs, so importing ``app.services`` or ``app.checks`` doesn't
load the web layer.
"""
import logging


def create_app(settings=None, services=None):
    """
    Creates and configures the CloudGauge Flask application.

    Args:
        settings (Settings, optional): Defaults to ``Settings.from_env()``, where
            ``CLOUDGAUGE_ENV`` picks the profile.
        services (Services, optional): The route handlers' dependencies. Defaults
            to ``build_services(settings)``, which creates GCP clients on first use.

    Returns:
        Flask: The configured application.

    In the ``production`` profile (the default), the legacy startup sequence that
    deployments rely on still runs: validate the required environment variables,
    resolve the worker URL, then create the Cloud Tasks queue if it's missing.
    Any failure raises, so a misconfigured Cloud Run revision fails to start with
    a clear log message. ``development`` and ``testing`` skip these steps.
    ``synthetic`` runs them too (it is production with a simulated data plane;
    see ``app.synthetic``) and marks every page and report with a banner.

    ``CLOUDGAUGE_ROLE`` decides which blueprints the app has (``app.routes``) and
    how the worker URL is found: a ``web`` service must be told it (``WORKER_URL``),
    a ``worker`` or ``all`` service discovers its own. Both create the queue.
    """
    from flask import Flask

    from app import identity
    from app.config import Settings
    from app.extensions import EXTENSION_KEY, build_services
    from app.routes import register_blueprints
    from app.services.tasks import ensure_queue_if_configured
    from app.utils import configure_logging

    settings = settings or Settings.from_env()
    configure_logging()

    # --- Flask App Initialization & Configuration ---
    app = Flask(__name__)
    app.config["TESTING"] = settings.is_testing
    app.config["CLOUDGAUGE_PROFILE"] = settings.profile
    app.config["CLOUDGAUGE_ROLE"] = settings.role

    if settings.startup_checks_enabled:
        # Fail fast, before any GCP call, if the deployment is missing configuration.
        settings.validate()

    services = services or build_services(settings)
    app.extensions[EXTENSION_KEY] = services

    if settings.startup_checks_enabled:
        # Deployments depend on both: Cloud Tasks calls {worker_url}/run-scan, and
        # nothing else creates the queue.
        services.get_worker_url()
        ensure_queue_if_configured(settings, client=services.get_tasks_client())
    else:
        logging.info(f"CloudGauge '{settings.profile}' profile: skipping startup checks (env validation, worker URL, task queue).")

    if services.report_banner:
        app.context_processor(lambda: {"banner": services.report_banner})
    if settings.serves_pages:
        # Who is signed in (behind Identity-Aware Proxy), for the pages' header. None: nobody / not behind IAP.
        app.context_processor(lambda: {"current_user": identity.current_user_email()})

    register_blueprints(app, settings.role)
    served = {'all': "the pages, the API and the Cloud Tasks endpoints", 'web': "the pages and the API (scans run on WORKER_URL)",
              'worker': "the Cloud Tasks endpoints only"}[settings.role]
    logging.info(f"CloudGauge role '{settings.role}': serving {served}.")
    return app
