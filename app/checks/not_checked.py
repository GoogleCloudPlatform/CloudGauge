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
"""The projects a check could not cover, reported instead of silently skipped.

A per-project check (Open Firewall Rules, GKE Hygiene, the cost recommenders,
...) logs and skips a project whose API call fails, so a project the scanner
cannot read (missing role, disabled API, quota, a transient 5xx) does not stop
the scan. Before this module the skip was invisible in the report: the check
still came out "Compliant" and the reader had no way to tell "nothing found"
from "not looked at".

Each check now collects its skipped projects in a :class:`NotChecked` and, after
its own record, writes them as one record named ``"Projects not checked"`` with
status ``Error`` in the check's category::

    {"Check": "Projects not checked", "Category": "Security & Identity", "Status": "Error",
     "Finding": [{"Project": "p1", "Skipped check": "Open Firewall Rules", "Reason": "403 ..."}, ...]}

The report groups records by name within a category, so every category page
shows at most one "Projects not checked" item: a table of project, check, and
reason that the reader can filter by project ID like any other. The record
carries its own ``Category`` because the one name is used in every category
(``categorize_findings`` honours it).

What is *not* reported, to keep the table meaningful in large organizations:

- A project in which the API that owns the resources is not enabled has none of
  them (no Compute Engine API, no VMs or firewall rules). Checks pass these APIs
  as ``resource_apis``; such projects are logged and left out. A disabled API
  that only *analyzes* resources (Recommender, Monitoring) is reported: the
  project may well have the resources.
- Errors about the request rather than the project (``is_request_error``: an
  invalid argument, a location where a recommender is not offered). The
  location loops of the cost and network checks hit these routinely.

The cost recommenders and the network insights are queried at the zones and
regions that location discovery (``get_active_compute_locations``) found in the
scanned projects. A project whose discovery failed is queried only at the
locations found in other projects, or at none when there are no others, and the
check itself may not notice (nothing queried, nothing failed). The runner passes
discovery failures to these two checks, which report such a project with the
discovery error and :func:`location_detail` unless every one of its queries
failed anyway (then the query error already says it was not checked). A project
without the Compute Engine API has no compute locations to discover and is not
reported for that (``LOCATION_DISCOVERY_APIS``).

This module imports only ``categories``: the checks import it, and the runner
and registry import the checks.
"""
import logging
import re

from google.api_core import exceptions as core_exceptions

from app.checks.categories import CATEGORY_MAP

# The "Check" name of the record. One item per category page in the report.
NOT_CHECKED = "Projects not checked"
# The longest reason the record keeps for one project (the log has the full error). Long
# enough for the whole "API has not been used in project ... Enable it by visiting ..." text.
MAX_REASON_LENGTH = 400

# Phrases of the "API not enabled" errors (REST: accessNotConfigured; gRPC: SERVICE_DISABLED).
API_DISABLED_MARKERS = ("has not been used in project", "it is disabled", "accessNotConfigured", "SERVICE_DISABLED")
# Where such an error names the API: the "Enable it by visiting .../apis/api/<service>/overview"
# link in the message, or the gRPC error details' service metadata (``key: "service"`` then
# ``value: "<service>"``, with real or escaped newlines between them depending on how the
# details were rendered).
_ENABLE_LINK = re.compile(r"/apis/api/([a-z0-9.-]+)/overview")
_SERVICE_METADATA = re.compile(r'key:\s*"service".{0,40}?value:\s*"([a-z0-9.-]+)"', re.S)

# Errors about the request itself, not about access to the project.
REQUEST_ERRORS = (core_exceptions.InvalidArgument, core_exceptions.OutOfRange, core_exceptions.NotFound,
                  core_exceptions.MethodNotImplemented, core_exceptions.MethodNotAllowed)


def describe_error(error):
    """``error`` as one bounded line for the report.

    A googleapiclient ``HttpError`` becomes ``"<status> <API message>"`` (its
    ``str`` is the whole response); anything else is its ``str``. Whitespace is
    collapsed and the text cut at ``MAX_REASON_LENGTH``.
    """
    status = getattr(getattr(error, "resp", None), "status", None)
    reason = getattr(error, "reason", None)
    text = f"{status} {reason}" if status and isinstance(reason, str) and reason.strip() else str(error)
    text = " ".join(text.split()) or type(error).__name__
    if len(text) > MAX_REASON_LENGTH:
        text = text[:MAX_REASON_LENGTH - 3].rstrip() + "..."
    return text


def disabled_api(error):
    """The API whose being disabled in the project caused ``error``.

    Returns the service name (``"compute.googleapis.com"``), ``""`` when the
    message says an API is disabled but does not name it, and ``None`` when
    ``error`` is not about a disabled API.
    """
    text = str(error)
    if not any(marker in text for marker in API_DISABLED_MARKERS):
        return None
    match = _ENABLE_LINK.search(text) or _SERVICE_METADATA.search(text)
    return match.group(1) if match else ""


def is_api_disabled(error):
    """Whether ``error`` says an API is not enabled in the project."""
    return disabled_api(error) is not None


# "in project <id> before", "?project=<id> then retry": the project an API error is about.
_PROJECT_MENTION = re.compile(r"\bproject[ =]([a-z][a-z0-9:.-]*[a-z0-9]|\d+)")


def mentioned_projects(error):
    """The project IDs or numbers an API error message names (``set()`` when it names none)."""
    return set(_PROJECT_MENTION.findall(str(error)))


def disabled_api_elsewhere(error, project_id, project_number=""):
    """Whether ``error`` says an API is disabled in a project *other than* ``project_id``.

    A per-project API (Service Health, Advisory Notifications) can also be
    disabled in the scanner's own project, in which case the message names that
    project and the same error would stop every project of the scan: the check
    reports it once as its own Error rather than as one skipped project per row.
    """
    if disabled_api(error) is None:
        return False
    named = mentioned_projects(error)
    return bool(named) and not (named & {str(project_id), str(project_number or "")})


def is_request_error(error):
    """Whether ``error`` is about the request, not about access to the project.

    An invalid argument or a not-found location means the request was wrong for
    that location (a recommender that is not offered there, say); the project
    could still be checked, so these are not recorded as skips.
    """
    return isinstance(error, REQUEST_ERRORS)


class NotChecked:
    """Collects the projects one check could not cover and writes them as one record.

    Args:
        check_name: The check's name in the report; must be a key of ``CATEGORY_MAP``
            (that is what decides the category the record is reported under).
        resource_apis: Services whose being disabled means the project has none of
            the resources the check looks at; such projects are logged, not recorded.

    Inside a check::

        skipped = NotChecked(CHECK_NAME, resource_apis=("compute.googleapis.com",))
        ...
            except Exception as e:
                skipped.add(project_id, e)
        ...
        sink.write_finding(job_id, ..., result)  # the check's own record first,
        skipped.write(sink, job_id)              # then the projects it could not check
    """

    def __init__(self, check_name, resource_apis=()):
        self.check_name = check_name
        self.category = CATEGORY_MAP[check_name]
        self.resource_apis = tuple(resource_apis)
        self.rows = []

    def add(self, project_id, error, detail=None, resource_apis=None):
        """Records that ``project_id`` was not checked because of ``error``.

        ``detail`` qualifies the check in the row ("3 of 8 recommenders"). A
        project whose resource API is disabled is logged and left out: there is
        nothing to check in it. ``resource_apis`` replaces the collector's for this
        one error (a step of the check that reads a different API).
        """
        service = disabled_api(error)
        apis = self.resource_apis if resource_apis is None else tuple(resource_apis)
        if apis and service is not None and service in (*apis, ""):
            logging.info(f"Skipping {self.check_name} for {project_id}: {service or 'the API'} is not enabled, so there is nothing to check")
            return
        logging.warning(f"Could not check {self.check_name} for {project_id}: {error}")
        skipped = self.check_name if not detail else f"{self.check_name} ({detail})"
        self.rows.append({"Project": project_id, "Skipped check": skipped, "Reason": describe_error(error)})

    def write(self, sink, job_id):
        """Writes the collected projects as one ``Projects not checked`` record; nothing if there are none."""
        if not self.rows:
            return
        record = {"Check": NOT_CHECKED, "Category": self.category, "Status": "Error", "Finding": list(self.rows)}
        file_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"NOT_CHECKED_{self.check_name}").strip("_")
        sink.write_finding(job_id, file_name, record)


def failures_by_reason(failures):
    """Groups ``{part: error}`` (recommender name -> its error) by reason.

    Returns ``[(error, [parts...]), ...]`` in first-seen order: one row per
    distinct reason, naming the parts (recommenders, insight types) it affected.
    """
    grouped = {}
    for part, error in failures.items():
        grouped.setdefault(describe_error(error), (error, []))[1].append(part)
    return list(grouped.values())


def describe_parts(parts, total, noun):
    """``"all 8 recommenders"`` or ``"3 of 8 recommenders: A, B, C"`` (the ``detail`` of :meth:`NotChecked.add`)."""
    if len(parts) >= total:
        return f"all {total} {noun}s"
    return f"{len(parts)} of {total} {noun}s: {', '.join(parts)}"


# The API location discovery reads (Compute Engine instances, addresses, forwarding
# rules). A project in which it is disabled has no compute locations: not a failure.
LOCATION_DISCOVERY_APIS = ("compute.googleapis.com",)


def location_detail(queried, total, noun):
    """The ``detail`` for a project whose location discovery failed: what that did to the check.

    ``queried`` says whether the check still queried the project somewhere (at the
    locations found in other projects); if not, none of its ``total`` parts ran.
    """
    if not queried:
        return f"all {total} {noun}s: no zones or regions were discovered to query"
    return "location discovery; queried only in zones and regions found in other projects"
