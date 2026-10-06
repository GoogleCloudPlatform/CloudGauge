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
"""HTTP routes, one blueprint per kind of caller.

- ``ui``      pages for people: ``/``, ``/scan``, ``/status/...``, ``/report/...``
- ``api``     JSON under ``/api``, called by those pages and by stored reports
- ``worker``  ``/run-scan``, called by Cloud Tasks

URLs, methods, request formats, response bodies, and status codes are the same
as in the legacy module. Reports already stored in GCS call the ``/api/get-*``
paths, and Cloud Tasks posts ``{scope, scope_id, job_id}`` to ``/run-scan``.
Endpoint names now carry their blueprint (``get_status`` is ``ui.get_status``).

Which blueprints a service registers depends on its ``CLOUDGAUGE_ROLE``
(``app.config.ROLES``): ``web`` has the pages and the API and no worker
endpoints, so nobody who passes Identity-Aware Proxy can post to
``/run-aggregation``; ``worker`` has only the Cloud Tasks endpoints; ``all``
has everything on one service.

Handlers get their dependencies from ``app.extensions.get_services()``.
"""
from app.routes import api, ui, worker

BLUEPRINTS = (ui.bp, api.bp, worker.bp)
BLUEPRINTS_BY_ROLE = {
    'all': BLUEPRINTS,
    'web': (ui.bp, api.bp),
    'worker': (worker.bp,),
}


def register_blueprints(app, role='all'):
    """Registers the CloudGauge blueprints that ``role`` serves on ``app``."""
    for blueprint in BLUEPRINTS_BY_ROLE[role]:
        app.register_blueprint(blueprint)
