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
"""Report view-model: turns categorized findings into plain data for the templates.

``build_report_context`` does everything the legacy ``generate_html_report`` did
except produce HTML: group findings by check and merge their statuses, evaluate
organization policies, score each category, count the overview cards, number
the remediation placeholders (``fix-N``), and pick each section's footer. The
templates in ``app/templates/report/`` only lay this data out.

Values that end up in the page are formatted here with the same f-string
expressions the legacy code used (``f"{value}"``, ``f"{score:.0f}"``), so the
report shows the same findings, statuses, and scores as the legacy one (the
tests compare them with ``helpers.report_facts``).

Layout for large organizations (plan item 6b). A scan of thousands of
projects can give one check tens of thousands of rows, so the report never
groups by project (hundreds of groups would bury the findings) and instead:

- orders each section's checks by severity, then name, and gives every check a
  summary line ("1,204 findings across 312 of 1,000 projects (31%)");
- includes at most ``MAX_ROWS_PER_CHECK`` rows of a check's table in the page
  (the CSV always has every row) and says so under the table;
- shows the first ``ROWS_PER_PAGE`` rows and lets the page's script reveal the
  rest, sort columns, and filter rows by project ID or any text.
"""
from dataclasses import dataclass, fields

from markupsafe import Markup

# The report's sections, in display order. The sidebar in report.html links to them.
REPORT_CATEGORY_ORDER = ("Security & Identity", "Cost Optimization", "Reliability & Resilience", "Operational Excellence & Observability")
ORG_POLICIES_KEY = "Organization Policies"

# Icons are HTML character references, so they are Markup: the report template autoescapes everything else.
ICON_CROSS, ICON_CHECK = Markup("&#10007;"), Markup("&#10003;")
# Which status wins when a check has several records (lower is more severe).
STATUS_PRIORITY = {"Action Required": 0, "Investigation Recommended": 1, "Informational": 2, "Compliant": 3, "Error": 4}
# The order of the checks within a section: what needs work first, then what could not be checked.
DISPLAY_ORDER = {"Action Required": 0, "Investigation Recommended": 1, "Error": 2, "Informational": 3, "Compliant": 4}
STATUS_STYLES = {
    "Action Required": {"icon": ICON_CROSS, "class": "action-required"}, "Investigation Recommended": {"icon": Markup("&#9888;"), "class": "investigation"},
    "Compliant": {"icon": ICON_CHECK, "class": "compliant"}, "Error": {"icon": Markup("&#10069;"), "class": "error"}, "Informational": {"icon": Markup("&#8505;"), "class": "informational"}
}
# Checks with these statuses get a placeholder for a Gemini remediation suggestion.
ACTIONABLE_STATUSES = ["Action Required", "Investigation Recommended"]
FAILING_STATUSES = ["Action Required", "Investigation Recommended", "Error"]

# The most rows of one check's details included in the HTML report. At ~200 bytes a
# row and ~25 checks this bounds the page at roughly 10 MB; the CSV has every row.
MAX_ROWS_PER_CHECK = 2000
# Rows shown before the reader asks for more (the rest are in the page, hidden).
ROWS_PER_PAGE = 50
# Column names (lowercase) that hold the project a row belongs to.
PROJECT_COLUMNS = ("project", "project id", "project_id")
# The noun of a check's summary line, by status ("finding" otherwise).
SUMMARY_NOUNS = {"Error": "error", "Informational": "entry"}


@dataclass(frozen=True)
class PolicyResult:
    """One best-practice policy compared with the effective policy (raw values)."""
    policy_id: str
    display_name: object
    expected_value: object
    current_value: str
    status: str


@dataclass(frozen=True)
class Details:
    """A check's details cell: a table if the details are dicts, otherwise lines of text.

    ``rows``/``lines`` hold at most ``MAX_ROWS_PER_CHECK`` entries; ``total_rows``
    counts them all and ``omitted_rows`` how many the page leaves to the CSV.
    """
    kind: str  # "table" or "text"
    headers: tuple = ()
    rows: tuple = ()
    lines: tuple = ()
    total_rows: int = 0
    omitted_rows: int = 0
    project_column: int | None = None  # index of the project column in ``headers``
    project_count: int | None = None  # distinct projects over all rows (None without a project column)


@dataclass(frozen=True)
class CheckItem:
    check_name: str
    status: str
    status_class: str
    icon: str
    details: Details | None
    fix_id: int | None  # the N of the remediation placeholder id "fix-N"
    summary: str | None = None  # "12 findings across 3 projects"; None when it would only repeat the table


@dataclass(frozen=True)
class StatusCount:
    """How many of a section's checks have a status (the strip under the section title)."""
    status: str
    count: int
    status_class: str


@dataclass(frozen=True)
class OrgPolicyRow:
    display_name: str
    expected_value: str
    current_value: str
    status: str
    status_class: str


@dataclass(frozen=True)
class OrgPolicyCategory:
    name: str
    rows: tuple


@dataclass(frozen=True)
class OrgPolicySummary:
    """The Organization Policies item shown first in the Security & Identity section."""
    categories: tuple
    compliant: int
    total: int
    status_class: str
    icon: str


@dataclass(frozen=True)
class Section:
    title: str
    section_id: str
    score: float
    score_display: str
    score_class: str
    org_policies: OrgPolicySummary | None
    checks: tuple
    footer: str | None  # "cost", "security", or None
    status_counts: tuple = ()  # a StatusCount per status present among ``checks``, in DISPLAY_ORDER


@dataclass(frozen=True)
class ScoreRow:
    category_name: str
    section_id: str
    score: float
    score_display: str
    score_class: str


@dataclass(frozen=True)
class Overview:
    action_count: int
    investigation_count: int
    compliant_count: int
    error_count: int


@dataclass(frozen=True)
class Coverage:
    """How much of the scope a sharded scan covered (shown above the overview cards)."""
    total_projects: int
    projects_scanned: int
    scanned_pct: str  # formatted, e.g. "98"
    projects_partial: int  # projects of shards that hit their time budget
    projects_not_scanned: int  # projects of shards that failed or never reported
    total_shards: int
    shards_failed: int
    shards_missing: int
    scope_checks: str  # "success", "timed_out", "failed", or "missing"
    complete: bool  # every project scanned and the scope-level checks ran

    @classmethod
    def from_dict(cls, coverage):
        """Builds the view-model from ``app.fanout.build_coverage``'s dict."""
        total = coverage["total_projects"]
        scanned = coverage["projects_scanned"]
        complete = (scanned == total and coverage["scope_checks"] == "success")
        return cls(
            total_projects=total, projects_scanned=scanned,
            scanned_pct=f"{(scanned / total * 100) if total else 100:.0f}",
            projects_partial=coverage["projects_partial"], projects_not_scanned=coverage["projects_not_scanned"],
            total_shards=coverage["total_shards"], shards_failed=coverage["shards_failed"],
            shards_missing=coverage["shards_missing"], scope_checks=coverage["scope_checks"], complete=complete,
        )


@dataclass(frozen=True)
class ReportContext:
    scope: str
    scope_id: str
    job_id: str
    scope_title: str
    overview: Overview
    score_summary: tuple
    sections: tuple  # only the sections that have checks or org policies
    # A notice rendered above the overview (the synthetic load mode sets it). None: nothing is rendered.
    banner: str | None = None
    # Sharded scans only: what the report covers. None: nothing is rendered.
    coverage: Coverage | None = None
    # Projects in the scanned scope, when known (summary lines then say "312 of 1,000 projects").
    total_projects: int | None = None
    rows_per_page: int = ROWS_PER_PAGE
    max_rows_per_check: int = MAX_ROWS_PER_CHECK

    def template_vars(self):
        """The top-level template variables (a shallow dict of the fields)."""
        return {f.name: getattr(self, f.name) for f in fields(self)}


def section_id_for(category_name):
    return category_name.lower().replace(' & ', '-').replace(' ', '-')


def score_class_for(score):
    return "high" if score > 90 else "medium" if score > 70 else "low"


def display_rank(status):
    """Where a check with ``status`` sorts within its section (unknown statuses rank with Informational)."""
    return DISPLAY_ORDER.get(status, DISPLAY_ORDER["Informational"])


def count_statuses(checks):
    """A ``StatusCount`` per status present among ``checks`` (CheckItems), in display order."""
    counts = {}
    for check in checks:
        counts[check.status] = counts.get(check.status, 0) + 1
    return tuple(StatusCount(status, counts[status], STATUS_STYLES.get(status, STATUS_STYLES["Informational"])["class"])
                 for status in sorted(counts, key=lambda s: (display_rank(s), s)))


def group_findings(findings_list):
    """Groups finding records by check name, merging details and keeping the most severe status."""
    grouped = {}
    status_priority = STATUS_PRIORITY
    for finding in findings_list:
        check_name = finding.get('Check')
        if not check_name: continue
        if check_name not in grouped:
            grouped[check_name] = {"details": [], "Status": finding.get('Status')}

        finding_detail = finding.get('Finding')

        # FIX: When the finding is already a list (like from cost checks), extend the details. Don't append the list itself.
        if isinstance(finding_detail, list):
            grouped[check_name]["details"].extend(finding_detail)
        elif finding_detail:
            grouped[check_name]["details"].append(finding_detail)

        if status_priority.get(finding.get('Status'), 99) < status_priority.get(grouped[check_name]['Status'], 99):
            grouped[check_name]['Status'] = finding.get('Status')
    return grouped


def build_details(details_list, max_rows=MAX_ROWS_PER_CHECK):
    """Returns a table if details are a list of dicts, otherwise text lines (legacy ``create_details_html``).

    Only the first ``max_rows`` rows (or lines) go into the page; ``total_rows``
    and ``project_count`` are computed over all of them.
    """
    if not details_list: return None
    if isinstance(details_list[0], dict):
        try:
            headers = details_list[0].keys()
            header_cells = tuple(f"{h}" for h in headers)
            rows = []
            for item in details_list:
                rows.append(tuple(f"{item.get(h, '')}" for h in headers))
        except Exception:
            return _text_details(details_list, max_rows)
        project_column = next((i for i, h in enumerate(header_cells) if h.strip().lower() in PROJECT_COLUMNS), None)
        project_count = len({row[project_column] for row in rows}) if project_column is not None else None
        return Details(kind="table", headers=header_cells, rows=tuple(rows[:max_rows]), total_rows=len(rows),
                       omitted_rows=max(0, len(rows) - max_rows), project_column=project_column, project_count=project_count)
    return _text_details(details_list, max_rows)


def _text_details(details_list, max_rows):
    lines = tuple(str(d) for d in details_list)
    return Details(kind="text", lines=lines[:max_rows], total_rows=len(lines), omitted_rows=max(0, len(lines) - max_rows))


def summarize_details(details, status, total_projects=None):
    """The one-line summary of a check's table: "1,204 findings across 312 of 1,000 projects (31%)".

    Returns None for text details and for single-row tables without a project
    column (an error message, say), where the line would only repeat the table.
    """
    if details is None or details.kind != "table" or (details.total_rows < 2 and details.project_column is None):
        return None
    noun = SUMMARY_NOUNS.get(status, "finding")
    count = details.total_rows
    plural = "" if count == 1 else ("ies" if noun.endswith("y") else "s")
    text = f"{count:,} {noun[:-1] if plural == 'ies' else noun}{plural}"
    projects = details.project_count
    if projects and total_projects and total_projects > 1:
        pct = projects / total_projects * 100
        pct_text = "<1" if 0 < pct < 1 else f"{pct:.0f}"
        text += f" across {projects:,} of {total_projects:,} projects ({pct_text}%)"
    elif projects and (projects > 1 or total_projects != 1):
        text += f" across {projects:,} project{'' if projects == 1 else 's'}"
    return text


def evaluate_org_policies(best_practices, current_policies):
    """
    Compares every best-practice policy with the effective organization policy.

    Shared by the HTML and CSV reports (the legacy code had one copy in each).

    Returns:
        list: ``(category, [PolicyResult, ...])`` pairs, sorted by category;
        categories without policies are left out.
    """
    evaluated = []
    for category, policies in sorted(best_practices.items()):
        if not policies: continue
        results = []
        for policy in policies:
            policy_id, details = policy['policyId'], policy
            status, current_value_str = "Not Configured", "N/A"
            if policy_id in current_policies:
                policy_details = current_policies[policy_id]
                if 'booleanPolicy' in policy_details:
                    current_value = policy_details['booleanPolicy'].get('enforced', False)
                    current_value_str = str(current_value)
                    status = "Compliant" if current_value_str.lower() == details['expectedValue'].lower() else "Non-compliant"
                else:
                    status, current_value_str = "Unsupported", "List Policy/Other"
            results.append(PolicyResult(policy_id, details['displayName'], details['expectedValue'], current_value_str, status))
        evaluated.append((category, results))
    return evaluated


def build_org_policy_summary(org_policy_data):
    """Builds the Organization Policies item from ``(best_practices, current_policies)``."""
    best_practices_by_category, current_policies = org_policy_data
    categories = []
    compliant_policy_count, total_policies = 0, 0
    for category, results in evaluate_org_policies(best_practices_by_category, current_policies):
        rows = []
        for result in results:
            total_policies += 1
            if result.status == "Compliant": compliant_policy_count += 1
            rows.append(OrgPolicyRow(
                display_name=f"{result.display_name}",
                expected_value=f"{result.expected_value}",
                current_value=result.current_value,
                status=result.status,
                status_class=result.status.lower().replace(' ', '-'),
            ))
        categories.append(OrgPolicyCategory(name=f"{category}", rows=tuple(rows)))
    # Determine status class for the LI item
    status_class = "compliant" if compliant_policy_count == total_policies else "action-required"
    icon = ICON_CHECK if status_class == "compliant" else ICON_CROSS
    return OrgPolicySummary(tuple(categories), compliant_policy_count, total_policies, status_class, icon)


def build_report_context(scope, scope_id, job_id, all_results, banner=None, coverage=None, total_projects=None):
    """
    Builds the data for the HTML report.

    Args:
        scope (str): The scope of the scan (organization, folder, project).
        scope_id (str): The ID of the scanned resource.
        job_id (str): The unique ID for this scan job.
        all_results (dict): Categorized findings, plus the optional
            ``"Organization Policies"`` entry ``(best_practices, current_policies)``.
        banner (str, optional): A notice to show at the top of the report.
        coverage (dict, optional): A sharded scan's coverage (``app.fanout.build_coverage``).
        total_projects (int, optional): Projects in the scope; the summary lines
            then give the share of projects a check found something in.
            Defaults to the coverage's total for sharded scans.

    Returns:
        ReportContext: Everything the report templates display.
    """
    if total_projects is None and coverage:
        total_projects = coverage["total_projects"]

    # --- CALCULATE SCORES AND DATA FOR ALL SECTIONS ---
    org_policy_summary = None
    if all_results.get(ORG_POLICIES_KEY):
        org_policy_summary = build_org_policy_summary(all_results[ORG_POLICIES_KEY])

    category_scores = {}
    all_other_findings = []
    for category_name in REPORT_CATEGORY_ORDER:
        findings = all_results.get(category_name, [])
        all_other_findings.extend(findings)
        grouped_data = group_findings(findings)
        pass_count = sum(1 for g in grouped_data.values() if g.get('Status') == 'Compliant')
        fail_count = sum(1 for g in grouped_data.values() if g.get('Status') in FAILING_STATUSES)
        if category_name == "Security & Identity" and org_policy_summary:
            pass_count += org_policy_summary.compliant
            fail_count += (org_policy_summary.total - org_policy_summary.compliant)
        total_for_score = pass_count + fail_count
        score = (pass_count / total_for_score) * 100 if total_for_score > 0 else 100
        category_scores[category_name] = score

    grouped_all_findings = group_findings(all_other_findings)
    action_count = sum(1 for g in grouped_all_findings.values() if g.get('Status') == 'Action Required')
    investigation_count = sum(1 for g in grouped_all_findings.values() if g.get('Status') == 'Investigation Recommended')
    compliant_count = sum(1 for g in grouped_all_findings.values() if g.get('Status') == 'Compliant')
    error_count = sum(1 for g in grouped_all_findings.values() if g.get('Status') == 'Error')
    if org_policy_summary:
        compliant_count += org_policy_summary.compliant
        action_count += (org_policy_summary.total - org_policy_summary.compliant)

    # --- BUILD EACH HIDDEN CATEGORY SECTION ---
    # Checks are listed by severity, then name. Remediation placeholders are numbered
    # fix-0, fix-1, ... across all sections, in display order.
    finding_counter = 0
    sections = []
    for category_name in REPORT_CATEGORY_ORDER:
        grouped_data = group_findings(all_results.get(category_name, []))
        org_content_for_section = org_policy_summary if category_name == "Security & Identity" else None
        if not grouped_data and not org_content_for_section:
            continue
        checks = []
        for check_name, group_data in sorted(grouped_data.items(), key=lambda item: (display_rank(item[1].get("Status")), item[0])):
            status = group_data.get("Status", "Informational")
            status_info = STATUS_STYLES.get(status, STATUS_STYLES["Informational"])
            fix_id = None
            if status in ACTIONABLE_STATUSES:
                fix_id = finding_counter
                finding_counter += 1
            details = build_details(group_data.get('details', []))
            checks.append(CheckItem(
                check_name=f"{check_name}",
                status=f"{status}",
                status_class=status_info['class'],
                icon=status_info['icon'],
                details=details,
                fix_id=fix_id,
                summary=summarize_details(details, status, total_projects),
            ))
        footer = None
        if category_name == "Cost Optimization":
            footer = "cost"
        elif category_name == "Security & Identity" and scope == 'organization':
            footer = "security"
        score = category_scores[category_name]
        sections.append(Section(
            title=category_name,
            section_id=section_id_for(category_name),
            score=score,
            score_display=f"{score:.0f}",
            score_class=score_class_for(score),
            org_policies=org_content_for_section,
            checks=tuple(checks),
            footer=footer,
            status_counts=count_statuses(checks),
        ))

    # --- THE SCORE SUMMARY TABLE ---
    score_summary = tuple(
        ScoreRow(category_name, section_id_for(category_name), score, f"{score:.0f}", score_class_for(score))
        for category_name, score in category_scores.items()
    )

    return ReportContext(
        scope=scope,
        scope_id=scope_id,
        job_id=job_id,
        scope_title=scope.capitalize(),
        overview=Overview(action_count, investigation_count, compliant_count, error_count),
        score_summary=score_summary,
        sections=tuple(sections),
        banner=banner,
        coverage=Coverage.from_dict(coverage) if coverage else None,
        total_projects=total_projects,
    )
