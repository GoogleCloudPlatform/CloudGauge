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
"""``app.checks.not_checked``: the projects a check could not cover become a
"Projects not checked" record instead of passing as compliant.

The unit here is the collector and its error classification, plus how the two
location-based checks report a project whose location discovery failed. The
other checks that use it are covered by ``test_beta_checks.py`` (the Security
checks against a project that answers 403), ``test_synthetic.py`` (a whole scan
in which every project answers 403) and ``test_reporting.py`` (how the record
is shown). The last cost tests cover the verdict the recommenders reach (v15.2):
a Compliant row when one answered with nothing, none when nobody could ask.
"""
import json
import logging
from types import SimpleNamespace

import httplib2
from google.api_core import exceptions as core_exceptions
from googleapiclient.errors import HttpError

from app import utils
from app.checks.cost import COST_RECOMMENDERS, NOTHING_FOUND, run_cost_recommendations
from app.checks.network import run_network_insights
from app.checks.not_checked import (LOCATION_DISCOVERY_APIS, MAX_REASON_LENGTH, NOT_CHECKED, NotChecked, describe_error,
                                    describe_parts, disabled_api, failures_by_reason, is_api_disabled, is_request_error,
                                    location_detail)

ENABLE_COMPUTE = ("Compute Engine API has not been used in project 123 before or it is disabled. Enable it by visiting "
                  "https://console.developers.google.com/apis/api/compute.googleapis.com/overview?project=123 then retry. "
                  "If you enabled this API recently, wait a few minutes for the action to propagate to our systems and retry.")
ENABLE_RECOMMENDER = ENABLE_COMPUTE.replace("Compute Engine API", "Cloud Recommender API").replace("compute.googleapis.com", "recommender.googleapis.com")
DENIED = "The caller does not have permission"


def http_error(status, message, reason="accessNotConfigured"):
    """A googleapiclient ``HttpError`` as the discovery clients raise it (status line plus a JSON error body)."""
    content = json.dumps({"error": {"code": status, "message": message, "errors": [{"message": message, "domain": "global", "reason": reason}]}}).encode()
    return HttpError(httplib2.Response({"status": status, "reason": "Forbidden"}), content,
                     uri="https://compute.googleapis.com/compute/v1/projects/p/global/firewalls?alt=json")


def written(skipped):
    """The records ``skipped.write`` produces: ``[(file name, record), ...]``."""
    records = []
    skipped.write(SimpleNamespace(write_finding=lambda job_id, name, record: records.append((job_id, name, record))), "job-1")
    return records


# --- Describing errors ---

def test_describe_error_is_one_bounded_line():
    assert describe_error(http_error(403, DENIED, "forbidden")) == f"403 {DENIED}"  # not the whole response
    assert describe_error(core_exceptions.PermissionDenied(DENIED)) == f"403 {DENIED}"
    assert describe_error(RuntimeError("line one\n   line\ttwo  ")) == "line one line two"
    assert describe_error(ValueError()) == "ValueError"
    long = describe_error(RuntimeError("x" * 1000))
    assert len(long) == MAX_REASON_LENGTH and long.endswith("...")


def test_disabled_api_names_the_service():
    assert disabled_api(http_error(403, ENABLE_COMPUTE)) == "compute.googleapis.com"  # the "Enable it by visiting" link
    grpc = core_exceptions.PermissionDenied(
        "Cloud Recommender API has not been used in project 123 before or it is disabled.",
        details=['reason: "SERVICE_DISABLED"\ndomain: "googleapis.com"\nmetadata {\n  key: "service"\n  value: "recommender.googleapis.com"\n}\n'])
    assert disabled_api(grpc) == "recommender.googleapis.com"  # the gRPC error details
    assert disabled_api(RuntimeError("accessNotConfigured")) == ""  # disabled, API not named
    assert disabled_api(core_exceptions.PermissionDenied(DENIED)) is None
    assert is_api_disabled(http_error(403, ENABLE_COMPUTE)) and not is_api_disabled(http_error(403, DENIED, "forbidden"))


def test_request_errors_are_about_the_request_not_the_project():
    assert all(is_request_error(e) for e in (core_exceptions.InvalidArgument("bad location"), core_exceptions.NotFound("no such recommender")))
    assert not any(is_request_error(e) for e in (core_exceptions.PermissionDenied(DENIED), core_exceptions.FailedPrecondition("billing"),
                                                  core_exceptions.ServiceUnavailable("503"), core_exceptions.ResourceExhausted("429"),
                                                  http_error(400, "bad"), RuntimeError("x")))


# --- The collector ---

def test_not_checked_records_the_project_the_check_and_the_reason(caplog):
    skipped = NotChecked("Open Firewall Rules", resource_apis=("compute.googleapis.com",))
    assert skipped.category == "Security & Identity"
    with caplog.at_level(logging.INFO):
        skipped.add("p-denied", core_exceptions.PermissionDenied(DENIED))
        skipped.add("p-flaky", http_error(503, "Policy checks are unavailable", "backendError"))
        skipped.add("p-no-compute", http_error(403, ENABLE_COMPUTE))  # no Compute API: no firewall rules to check
        skipped.add("p-unnamed-api", RuntimeError("accessNotConfigured"))  # disabled and unnamed: taken to be the resource API
        skipped.add("p-no-recommender", http_error(403, ENABLE_RECOMMENDER))  # another API: the project is reported
    assert skipped.rows == [
        {"Project": "p-denied", "Skipped check": "Open Firewall Rules", "Reason": f"403 {DENIED}"},
        {"Project": "p-flaky", "Skipped check": "Open Firewall Rules", "Reason": "503 Policy checks are unavailable"},
        {"Project": "p-no-recommender", "Skipped check": "Open Firewall Rules", "Reason": f"403 {ENABLE_RECOMMENDER}"},
    ]
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings[0] == f"Could not check Open Firewall Rules for p-denied: 403 {DENIED}" and len(warnings) == 3
    assert [r.message for r in caplog.records if r.levelno == logging.INFO] == [
        "Skipping Open Firewall Rules for p-no-compute: compute.googleapis.com is not enabled, so there is nothing to check",
        "Skipping Open Firewall Rules for p-unnamed-api: the API is not enabled, so there is nothing to check"]
    assert written(skipped) == [("job-1", "NOT_CHECKED_Open_Firewall_Rules", {
        "Check": NOT_CHECKED, "Category": "Security & Identity", "Status": "Error", "Finding": skipped.rows})]


def test_a_disabled_api_is_reported_unless_it_is_the_checks_resource_api():
    """Without ``resource_apis`` (the Recommender-based checks) a disabled API is a skipped project like any other."""
    skipped = NotChecked("Cost-Saving Recommendations")
    skipped.add("p-1", http_error(403, ENABLE_COMPUTE))
    skipped.add("p-2", RuntimeError("accessNotConfigured"))
    assert [row["Project"] for row in skipped.rows] == ["p-1", "p-2"]
    assert written(skipped)[0][2]["Category"] == "Cost Optimization"


def test_nothing_is_written_without_skips_and_file_names_are_safe():
    assert written(NotChecked("GKE Hygiene")) == []
    skipped = NotChecked("VPC Firewall Complexity (>150 Rules)")
    skipped.add("p-1", RuntimeError("boom"), detail="3 of 8 recommenders: A, B, C")
    ((_, file_name, record),) = written(skipped)
    assert file_name == "NOT_CHECKED_VPC_Firewall_Complexity_150_Rules"
    assert record["Finding"] == [{"Project": "p-1", "Skipped check": "VPC Firewall Complexity (>150 Rules) (3 of 8 recommenders: A, B, C)", "Reason": "boom"}]
    assert record["Category"] == "Operational Excellence & Observability"


def test_failures_are_grouped_by_reason_and_described_by_part():
    denied, flaky = core_exceptions.PermissionDenied(DENIED), core_exceptions.ServiceUnavailable("try later")
    grouped = failures_by_reason({"VM Rightsizing": denied, "Idle Persistent Disks": flaky, "Low Utilization VMs": core_exceptions.PermissionDenied(DENIED)})
    assert grouped == [(denied, ["VM Rightsizing", "Low Utilization VMs"]), (flaky, ["Idle Persistent Disks"])]
    assert describe_parts(["A", "B", "C"], 8, "recommender") == "3 of 8 recommenders: A, B, C"
    assert describe_parts(list("ABCDEFGH"), 8, "insight type") == "all 8 insight types"


# --- Location discovery failures ---

def test_resource_apis_can_be_overridden_per_error_and_location_details_are_worded():
    """A check's discovery step reads the Compute API even when its own queries go elsewhere."""
    skipped = NotChecked("Cost-Saving Recommendations")
    skipped.add("p-no-compute", http_error(403, ENABLE_COMPUTE), resource_apis=LOCATION_DISCOVERY_APIS)  # nothing to discover
    skipped.add("p-no-compute-2", http_error(403, ENABLE_COMPUTE))  # the collector's own rule still applies otherwise
    assert [row["Project"] for row in skipped.rows] == ["p-no-compute-2"]
    assert location_detail(False, 8, "recommender") == "all 8 recommenders: no zones or regions were discovered to query"
    assert location_detail(True, 8, "insight type") == "location discovery; queried only in zones and regions found in other projects"


def not_checked_rows(sink):
    """The ``Projects not checked`` rows a check wrote to ``sink`` (a ``FakeSink``)."""
    return [row for record in sink.records if record["Check"] == NOT_CHECKED for row in record["Finding"]]


class FakeSink:
    def __init__(self):
        self.records = []

    def write_finding(self, job_id, name, record):
        self.records.append(record)


PROJECTS = [{"projectId": "p-ok"}, {"projectId": "p-denied"}, {"projectId": "p-flaky"}, {"projectId": "p-no-compute"}]
DISCOVERY_ERRORS = {"p-denied": http_error(403, DENIED, "forbidden"), "p-flaky": http_error(503, "Backend Error", "backendError"),
                    "p-no-compute": http_error(403, ENABLE_COMPUTE)}


def test_cost_check_reports_a_project_whose_locations_could_not_be_discovered(gcp):
    """Without discovered zones or regions the cost recommenders are never queried, so a project
    whose discovery failed would pass silently; it is reported with the discovery error instead."""
    sink = FakeSink()
    run_cost_recommendations("org", PROJECTS, [], ["global"], "job-1", DISCOVERY_ERRORS, sink=sink)
    assert gcp.recommender.parents == []  # nothing was queried ('global' is not a zone or region)
    assert not_checked_rows(sink) == [
        {"Project": "p-denied", "Reason": f"403 {DENIED}",
         "Skipped check": "Cost-Saving Recommendations (all 8 recommenders: no zones or regions were discovered to query)"},
        {"Project": "p-flaky", "Reason": "503 Backend Error",
         "Skipped check": "Cost-Saving Recommendations (all 8 recommenders: no zones or regions were discovered to query)"},
    ]  # p-ok was not in error; p-no-compute has no Compute Engine API, hence no compute locations
    assert cost_records(sink) == {}  # no recommender was asked, so none reached a verdict (v15.2)


def test_cost_check_does_not_repeat_a_project_whose_every_query_failed(gcp):
    """With locations from other projects the project is queried there: a denied project already has
    its "all 8 recommenders" row, a project whose queries succeed is reported as partially covered."""
    gcp.recommender.project_errors["p-denied"] = core_exceptions.PermissionDenied(DENIED)
    sink = FakeSink()
    run_cost_recommendations("org", PROJECTS, ["us-central1-a"], ["us-central1", "global"], "job-1", DISCOVERY_ERRORS, sink=sink)
    assert {parent.split("/")[1] for parent in gcp.recommender.parents} == {p["projectId"] for p in PROJECTS}
    assert not_checked_rows(sink) == [
        {"Project": "p-denied", "Skipped check": "Cost-Saving Recommendations (all 8 recommenders)", "Reason": f"403 {DENIED}"},
        {"Project": "p-flaky", "Reason": "503 Backend Error",
         "Skipped check": "Cost-Saving Recommendations (location discovery; queried only in zones and regions found in other projects)"},
    ]
    assert {check: status for check, (status, _) in cost_records(sink).items()} == {check: "Compliant" for check in COST_RECOMMENDERS}  # the other three answered


# --- The cost checks reach a verdict (v15.2) ---

def cost_records(sink):
    """``{check: (status, finding)}`` of the cost checks' records in ``sink`` (the *Projects not checked* record left out)."""
    return {record["Check"]: (record["Status"], record["Finding"]) for record in sink.records if record["Check"] != NOT_CHECKED}


def recommendation(resource, description, saving=12.0):
    """What ``parse_recommendation`` reads of a Recommendation proto."""
    cost = SimpleNamespace(units=-int(saving), nanos=-int(round((saving % 1) * 1e9)), currency_code="USD")
    return SimpleNamespace(name=f"recommendations/{resource}", description=description, recommender_subtype="DELETE",
                           content=SimpleNamespace(overview={"resourceName": resource}, operation_groups=[]),
                           primary_impact=SimpleNamespace(cost_projection=SimpleNamespace(cost=cost)))


def test_a_recommender_that_answered_with_nothing_is_compliant(gcp):
    """A recommender that answered somewhere and had nothing to recommend reached a verdict, which the score counts
    (app.reporting.scoring): it is written as Compliant with an all-clear row, like every other check."""
    sink = FakeSink()
    run_cost_recommendations("org", [{"projectId": "p-ok"}], ["us-central1-a"], ["us-central1", "global"], "job-1", sink=sink)
    assert cost_records(sink) == {check: ("Compliant", [{"Status": NOTHING_FOUND[check]}]) for check in COST_RECOMMENDERS}
    assert [record["Check"] for record in sink.records] == list(COST_RECOMMENDERS) and not_checked_rows(sink) == []  # in the report's order
    assert NOTHING_FOUND == {
        "Idle Cloud SQL Instances": "No idle Cloud SQL instances found.", "Low Utilization VMs": "No low-utilization VMs found.",
        "VM Rightsizing": "No VM rightsizing recommendations found.", "Unassociated IPs": "No unassociated IP addresses found.",
        "Idle Load Balancers": "No idle load balancers found.", "Idle Persistent Disks": "No idle persistent disks found.",
        "Underutilized Reservations": "No underutilized reservations found.", "Idle Reservations": "No idle reservations found."}


def test_a_recommendation_anywhere_outweighs_the_all_clear_and_a_denied_project_is_still_reported(gcp):
    """One project has an idle disk and the other answers 403 to everything: the disk check is Action Required, the
    seven others Compliant on the strength of the project that answered, and the denied project is on the not-checked
    rows — the contract every other check has."""
    gcp.recommender.recommendations[COST_RECOMMENDERS["Idle Persistent Disks"][0]] = [recommendation("old-boot-disk", "Delete the idle disk.")]
    gcp.recommender.project_errors["p-denied"] = core_exceptions.PermissionDenied(DENIED)
    sink = FakeSink()
    run_cost_recommendations("org", [{"projectId": "p-ok"}, {"projectId": "p-denied"}], ["us-central1-a"], ["us-central1"], "job-1", sink=sink)
    records = cost_records(sink)
    assert records["Idle Persistent Disks"] == ("Action Required", [
        {"Project": "p-ok", "Resource Name": "old-boot-disk", "Recommendation": "Delete the idle disk.", "Est. Monthly Saving": "12.00 USD"}])
    assert {check: status for check, (status, _) in records.items()} == {
        check: "Action Required" if check == "Idle Persistent Disks" else "Compliant" for check in COST_RECOMMENDERS}
    assert not_checked_rows(sink) == [{"Project": "p-denied", "Skipped check": "Cost-Saving Recommendations (all 8 recommenders)", "Reason": f"403 {DENIED}"}]


def test_a_recommender_nobody_could_ask_reaches_no_verdict(gcp):
    """Every call failed: no Compliant row is written, so the category reads *Not assessed* rather than 100%, and the
    failure is on the not-checked rows. Nothing to query (no zone or region) writes nothing at all."""
    gcp.recommender.project_errors["p-denied"] = core_exceptions.PermissionDenied(DENIED)
    sink = FakeSink()
    run_cost_recommendations("org", [{"projectId": "p-denied"}], ["us-central1-a"], ["us-central1"], "job-1", sink=sink)
    assert cost_records(sink) == {} and [row["Project"] for row in not_checked_rows(sink)] == ["p-denied"]
    sink = FakeSink()
    run_cost_recommendations("org", [{"projectId": "p-ok"}], [], ["global"], "job-1", sink=sink)
    assert sink.records == []


def test_a_recommender_not_offered_where_it_was_asked_is_neither_a_failure_nor_an_answer(gcp):
    """asia-south1 answers 400 for Idle Load Balancers: not the project's fault (no not-checked row), and no verdict
    either — with no other location to ask, the check is absent from the scan rather than Compliant."""
    gcp.recommender.errors[COST_RECOMMENDERS["Idle Load Balancers"][0]] = core_exceptions.InvalidArgument("The recommender is not offered in this location.")
    sink = FakeSink()
    run_cost_recommendations("org", [{"projectId": "p-ok"}], ["asia-south1-a"], ["asia-south1"], "job-1", sink=sink)
    records = cost_records(sink)
    assert "Idle Load Balancers" not in records and len(records) == 7 and not_checked_rows(sink) == []


def test_network_check_reports_a_project_whose_locations_could_not_be_discovered(gcp):
    """Network Insights always queries 'global', so the project is queried; a denied project has its
    "all 8 insight types" row and nothing more, a project whose queries succeed is partially covered."""
    gcp.recommender.project_errors["p-denied"] = core_exceptions.PermissionDenied(DENIED)
    sink = FakeSink()
    run_network_insights("org", PROJECTS, [], ["global"], "job-1", DISCOVERY_ERRORS, sink=sink)
    assert not_checked_rows(sink) == [
        {"Project": "p-denied", "Skipped check": "Network Insights (all 8 insight types)", "Reason": f"403 {DENIED}"},
        {"Project": "p-flaky", "Reason": "503 Backend Error",
         "Skipped check": "Network Insights (location discovery; queried only in zones and regions found in other projects)"},
    ]


# --- call_api_with_backoff reports the failures it swallows ---

def test_call_api_with_backoff_reports_the_error_it_returns_an_empty_result_for(monkeypatch):
    monkeypatch.setattr(utils.time, "sleep", lambda seconds: None)
    seen = []
    assert utils.call_api_with_backoff(lambda: ["ok"], on_error=seen.append) == ["ok"] and seen == []

    def denied():
        raise core_exceptions.PermissionDenied(DENIED)

    assert utils.call_api_with_backoff(denied, "a call", on_error=seen.append) == []
    assert utils.call_api_with_backoff(denied, "a call") == []  # the callback is optional
    attempts = []

    def throttled():
        attempts.append(1)
        raise core_exceptions.ResourceExhausted("quota")

    assert utils.call_api_with_backoff(throttled, "a call", on_error=seen.append) == [] and len(attempts) == 5
    assert [type(e).__name__ for e in seen] == ["PermissionDenied", "ResourceExhausted"]  # once per failed call, after the last retry
