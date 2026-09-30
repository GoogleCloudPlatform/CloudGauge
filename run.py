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
"""Local development server: ``python run.py``.

Production doesn't use this file: the container runs ``gunicorn cloudgauge:app``
(see the Dockerfile), and the image doesn't include ``run.py``.

Environment:

- ``CLOUDGAUGE_ENV``: defaults to ``development``, which skips the production
  startup checks (env validation, worker URL lookup, queue creation), so the UI
  starts without any GCP configuration. Set it to ``production`` (with the
  required variables and Application Default Credentials) to run the full
  startup sequence against real GCP.
- ``HOST`` (default ``127.0.0.1``) and ``PORT`` (default ``8080``). The default
  host keeps the debugger off the network; set ``HOST=0.0.0.0`` deliberately.
- ``FLASK_DEBUG``: debugger and auto-reload, on unless set to ``0``/``false``.

Starting a scan locally also needs the required variables (``PROJECT_ID``,
``LOCATION``, ``TASK_QUEUE``, ``RESULTS_BUCKET``, ``SERVICE_ACCOUNT_EMAIL``),
credentials (``gcloud auth application-default login``), and ``WORKER_URL``:
Cloud Tasks delivers the scan to ``{WORKER_URL}/run-scan``, which must be
reachable from Google Cloud.
"""
import os

from app import create_app

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080


def _flag(value, default):
    if value is None or not value.strip():
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


def main():
    """Builds the app (``development`` profile unless ``CLOUDGAUGE_ENV`` says otherwise) and serves it."""
    os.environ.setdefault("CLOUDGAUGE_ENV", "development")
    app = create_app()
    app.run(
        host=os.environ.get("HOST", DEFAULT_HOST),
        port=int(os.environ.get("PORT", DEFAULT_PORT)),
        debug=_flag(os.environ.get("FLASK_DEBUG"), default=True),
    )


if __name__ == "__main__":
    main()
