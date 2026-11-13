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
"""The shapes of the identifiers every request carries (v18.6.1).

A scope is one of three words; a scope ID is the number of an organization or
folder, or a project ID; a job ID is the UUID ``POST /scan`` minted. Every
route and every Cloud Tasks body passes its values through here before any of
them reaches a bucket key, a task body or an API call — the page routes answer
400 with the message, the worker routes too (Cloud Tasks retries a non-2xx a
bounded number of times either way; a 400 only makes the log honest).

``app.services.results_store`` keeps its own, coarser guard on the key parts
(no slash, no ``..``, a short allow-list of characters): the routes decide what
an identifier *means*, the store refuses to interpolate anything that could
reach another prefix even if a future caller forgets to validate.
"""
import re

SCOPES = ("organization", "folder", "project")
# An organization or folder number.
NUMERIC_ID = re.compile(r"^[0-9]{1,20}$")
# A project ID: 6-30 characters, a letter first, letters, digits and hyphens, not a hyphen last — optionally
# behind the domain of a domain-scoped project (``example.com:my-project``), the form Resource Manager still issues.
PROJECT_ID = re.compile(r"^(?:[a-z0-9][a-z0-9.-]{0,62}:)?[a-z][a-z0-9-]{4,28}[a-z0-9]$")
# A job ID: the lower-case UUID ``uuid.uuid4()`` writes (version-agnostic, so every job ever minted stays readable).
JOB_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# A shard's name (``app.fanout.plan_shards``): the scope shard, or a numbered project shard.
SHARD_ID = re.compile(r"^(?:scope|shard-[0-9]{1,6})$")
REQUESTED_BY_MAX_CHARS = 320  # an email address, or ``schedule: <name>``
MAX_COUNT = 1_000_000  # sweep numbers: anything larger is not ours


class RequestError(ValueError):
    """A request value that is not what the route accepts; ``str(error)`` is the message of the 400."""


def _text(value, what):
    if value is None:
        raise RequestError(f"{what} is required.")
    if not isinstance(value, str):
        raise RequestError(f"{what} must be a string.")
    value = value.strip()
    if not value:
        raise RequestError(f"{what} is required.")
    return value


def clean_scope(value):
    """One of ``organization``, ``folder`` or ``project``."""
    scope = _text(value, "scope")
    if scope not in SCOPES:
        raise RequestError("scope must be organization, folder or project.")
    return scope


def clean_scope_id(scope, value):
    """The scope's ID: an organization or folder number, or a project ID."""
    scope_id = _text(value, "scope_id")
    if scope == "project":
        if not PROJECT_ID.match(scope_id):
            raise RequestError("scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.")
    elif not NUMERIC_ID.match(scope_id):
        raise RequestError(f"scope_id must be the {scope}'s number.")
    return scope_id


def clean_any_scope_id(value):
    """A scope ID where the URL names no scope (the report and status routes): a number or a project ID."""
    scope_id = _text(value, "scope_id")
    if NUMERIC_ID.match(scope_id) or PROJECT_ID.match(scope_id):
        return scope_id
    raise RequestError("scope_id must be an organization or folder number, or a project ID.")


def clean_job_id(value):
    """A job ID as ``POST /scan`` mints them (a lower-case UUID)."""
    job_id = _text(value, "job_id")
    if not JOB_ID.match(job_id):
        raise RequestError("job_id must be a UUID.")
    return job_id


def clean_shard_id(value):
    """A shard's name as ``app.fanout`` plans them: ``scope`` or ``shard-NNN``."""
    shard_id = _text(value, "shard_id")
    if not SHARD_ID.match(shard_id):
        raise RequestError("shard_id must be scope or shard-NNN.")
    return shard_id


def clean_count(value, what, default=None):
    """A non-negative integer (a sweep number), given as an int or a string of digits."""
    if value is None and default is not None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise RequestError(f"{what} must be a non-negative integer.")
    if isinstance(value, str):
        value = value.strip()
        if not value.isdigit():
            raise RequestError(f"{what} must be a non-negative integer.")
        value = int(value)
    if value < 0 or value > MAX_COUNT:
        raise RequestError(f"{what} must be a non-negative integer.")
    return value


def clean_requested_by(value):
    """Who asked for the scan: an email or ``schedule: <name>``; ``None`` when absent."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    who = _text(value, "requested_by")
    if len(who) > REQUESTED_BY_MAX_CHARS or not who.isprintable():
        raise RequestError("requested_by must be a short, printable name.")
    return who


def clean_body(data):
    """The JSON object of a worker body, or raises."""
    if not isinstance(data, dict):
        raise RequestError("The body must be a JSON object.")
    return data


def clean_scan_body(data):
    """``/run-scan``'s body: ``scope``, ``scope_id``, ``job_id`` and the optional ``requested_by``, cleaned."""
    data = clean_body(data)
    scope = clean_scope(data.get("scope"))
    cleaned = {"scope": scope, "scope_id": clean_scope_id(scope, data.get("scope_id")), "job_id": clean_job_id(data.get("job_id"))}
    requested_by = clean_requested_by(data.get("requested_by"))
    if requested_by:
        cleaned["requested_by"] = requested_by
    return cleaned


def clean_shard_body(data):
    """``/scan-shard``'s body: the scan body plus ``shard_id``."""
    cleaned = clean_scan_body(data)
    cleaned["shard_id"] = clean_shard_id(data.get("shard_id"))
    return cleaned


def clean_sweep_body(data):
    """``/sweep``'s body: the scan body plus ``sweep`` (1 when absent, as the first sweep)."""
    cleaned = clean_scan_body(data)
    cleaned["sweep"] = clean_count(data.get("sweep"), "sweep", default=1)
    return cleaned
