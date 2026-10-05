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
"""The Scorecard (v15.1): the report's review page, built from the ``ReportContext``.

A report has two summary pages for two readers. The Overview is the
operator's working page: the four counts, the review scores with their bars
and links, the full Changes card, *Draft fixes*. The Scorecard is the
one-pager for the people who will not open the category pages - a quarterly
review, a leadership update: four stoplights, each with a state and the
evidence behind it; what moved since the previous scan, in one line; the ten
actions to take away; the executive summary (Gemini's, generated on this
page); and two exports built from the same model, the action-plan CSV and a
Markdown copy. It prints on one page.

Everything on it is sourced from the context, so the page states nothing the
rest of the report cannot back: scores and states from the sections
(``Section.score_class`` - above 90 *Healthy*, above 70 *Needs attention*,
else *At risk*, the bands the score bars already use), deltas and status
changes from ``app.reporting.changes``, projects and rows from the check
details, fixes from the remediation blocks.

The stoplights follow the playbook's pillars; each one sits over one report
category. Velocity & Innovation has no checks yet, so it has no stoplight.
"""
import csv
import io
from dataclasses import dataclass

from app.checks.categories import INCIDENT_STATE
from app.reporting.changes import ORG_POLICIES_CHECK
from app.reporting.context import ACTIONABLE_STATUSES, display_rank

# The stoplights, in the order the page shows them, each over one report category.
PILLARS = (("Stability", "Reliability & Resilience"), ("Security", "Security & Identity"),
           ("Operations", "Operational Excellence & Observability"), ("Efficiency", "Cost Optimization"))
STOPLIGHT_OF = {category: name for name, category in PILLARS}
# A stoplight's state, by the score band of its category (app.reporting.context.score_class_for).
STATE = {"high": "Healthy", "medium": "Needs attention", "low": "At risk"}
# Failing checks listed under Top actions; the rest are counted ("N more failing checks on the category pages").
TOP_ACTIONS = 10
# Status changes named on the since line before "and N more" (the Overview's Changes card has them all).
INLINE_STATUS_CHANGES = 3
# The Stability line adds this check's tally: incidents that affected the scope in the last 90 days.
INCIDENTS_CHECK = "Service Health Incidents"
# The action-plan CSV: the ranked actions, then two blank columns for the owner to fill in.
ACTION_PLAN_COLUMNS = ("Priority", "Check", "Category", "Status", "Projects affected", "Findings", "Fix in report", "Owner", "Target date")
FIX_IN_REPORT = "yes"


@dataclass(frozen=True)
class Stoplight:
    """One pillar: its state, its score with the change since the previous scan, and the evidence line."""
    name: str  # "Stability"
    category: str  # the report category it sits over
    section_id: str
    score_display: str  # "80"
    score_class: str  # high / medium / low: the pill's and the lamp's class
    state: str  # Healthy / Needs attention / At risk
    delta_display: str | None  # "+80", "−6", "—"; None on a first scan
    delta_class: str | None  # up / down / flat
    evidence: str  # "8 of 10 checks compliant · 1 project with findings · 4 incidents impacted you in 90 days, 0 active"


@dataclass(frozen=True)
class Action:
    """One of the Top actions: a failing check, ranked by status, then projects affected, then findings."""
    rank: int
    check_name: str
    section_id: str
    slug: str  # #<section_id>-<slug> opens the check on its category page
    category: str  # the stoplight's name, not the report category's
    status: str
    status_class: str
    projects: int | None  # distinct projects in the check's rows; None when its table has no project column
    findings: int  # the check's rows (one per finding), or its lines for text details
    fix_in_report: bool  # the check ships its command (the Fix block under its table); the others are drafted on request
    since: str  # "+1 new · −21 resolved · was Compliant", "not compared (new check)"; "" when nothing moved or on a first scan


@dataclass(frozen=True)
class Since:
    """The line under the stoplights: what moved since the previous scan."""
    previous_job_id: str
    previous_at: str
    new: int
    resolved: int
    status_changes: tuple  # "Check Before → After", regressions first
    projects_then: int | None
    projects_now: int | None

    @property
    def headline(self):
        """The status changes named on the page; the rest are a count with a link to the Changes card."""
        return self.status_changes[:INLINE_STATUS_CHANGES]

    @property
    def more_status_changes(self):
        return max(0, len(self.status_changes) - INLINE_STATUS_CHANGES)


@dataclass(frozen=True)
class Scorecard:
    scope_title: str
    scope_id: str
    job_id: str
    generated_at: str
    generated_ts: str
    coverage_text: str  # "52 of 52 projects" (the Markdown copy's header; the page has the report header above it)
    stoplights: tuple
    actions: tuple
    more_actions: int  # failing checks beyond TOP_ACTIONS
    org_line: str | None  # "3 of 6 organization policies differ from the recommendation"; None when none differ or not checked
    could_not_check: tuple  # "Open Firewall Rules (2 projects)": checks in Error
    since: Since | None  # None on a first scan


def projects_affected(items):
    """Distinct projects across the rows of ``items`` (None when no item has a project column)."""
    seen, any_column = set(), False
    for item in items:
        details = item.details
        if details is None or details.kind != "table" or details.project_column is None:
            continue
        any_column = True
        for row in details.rows:
            if details.project_column < len(row):
                seen.add(str(row[details.project_column]))
    return len(seen) if any_column else None


def since_text(change):
    """An action's *Since last scan* cell: the check's change chip, then the status it had."""
    if change is None:
        return ""
    bits = [change.chip] if change.chip else []
    if change.previous_status and not change.note:
        bits.append(f"was {change.previous_status}")
    return " · ".join(bits)


def plural(count, noun):
    return f"{count:,} {noun}{'' if count == 1 else 's'}"


def incidents_text(section):
    """The Stability line's incident tally, from the Service Health briefing (None when the scope has no briefing)."""
    item = next((check for check in section.checks if check.check_name == INCIDENTS_CHECK), None)
    if item is None or item.details is None or item.details.kind != "table":
        return None
    headers = list(item.details.headers)
    state_column = headers.index(INCIDENT_STATE) if INCIDENT_STATE in headers else None
    total = item.details.total_rows
    if not total:
        return "no incidents impacted you in 90 days"
    active = sum(1 for row in item.details.rows if state_column is not None and str(row[state_column]).upper() == "ACTIVE")
    return f"{plural(total, 'incident')} impacted you in 90 days, {active} active"


def build_stoplights(context):
    sections = {section.title: section for section in context.sections}
    score_rows = {row.category_name: row for row in context.score_summary}
    category_changes = {row.category_name: row for row in context.changes.categories} if context.changes else {}
    stoplights = []
    for name, category in PILLARS:
        section, row = sections[category], score_rows[category]
        failing = [item for item in section.checks if item.status in ACTIONABLE_STATUSES]
        evidence = [f"{row.pass_count:,} of {plural(row.pass_count + row.fail_count, 'check')} compliant"]
        affected = projects_affected(failing)
        if affected:
            evidence.append(f"{plural(affected, 'project')} with findings")
        incidents = incidents_text(section) if category == "Reliability & Resilience" else None
        if incidents:
            evidence.append(incidents)
        change = category_changes.get(category)
        stoplights.append(Stoplight(
            name=name, category=category, section_id=section.section_id,
            score_display=section.score_display, score_class=section.score_class, state=STATE[section.score_class],
            delta_display=change.delta_display if change else None, delta_class=change.delta_class if change else None,
            evidence=" · ".join(evidence),
        ))
    return tuple(stoplights)


def rank_key(item, projects, findings):
    # Action Required before Investigation Recommended, then the most projects, then the most findings, then the name.
    return (display_rank(item.status), -(projects or 0), -findings, item.check_name)


def build_actions(context):
    """``(actions, more)``: the failing checks ranked, the first TOP_ACTIONS as Actions and the count of the rest."""
    candidates = []
    for section in context.sections:
        for item in section.checks:
            if item.status not in ACTIONABLE_STATUSES:
                continue
            details = item.details
            projects = details.project_count if details is not None else None
            findings = 0 if details is None else (details.total_rows if details.kind == "table" else len(details.lines))
            candidates.append((rank_key(item, projects, findings), section, item, projects, findings))
    candidates.sort(key=lambda candidate: candidate[0])
    actions = tuple(
        Action(rank=rank, check_name=item.check_name, section_id=section.section_id, slug=item.slug,
               category=STOPLIGHT_OF[section.title], status=item.status, status_class=item.status_class,
               projects=projects, findings=findings, fix_in_report=bool(item.details is not None and item.details.fix_lines),
               since=since_text(item.change))
        for rank, (_, section, item, projects, findings) in enumerate(candidates[:TOP_ACTIONS], start=1))
    return actions, max(0, len(candidates) - TOP_ACTIONS)


def build_since(changes):
    if not changes:
        return None
    entries = [entry for row in changes.categories for entry in row.entries if entry.before]
    # Regressions first: a check that got worse matters more on a scorecard than ten that were fixed. The bare status
    # (after_status) ranks and reads; the "not compared" note an entry may carry stays on the Overview's Changes card.
    entries.sort(key=lambda entry: (display_rank(entry.after_status) >= display_rank(entry.before), display_rank(entry.after_status)))
    return Since(previous_job_id=changes.previous_job_id, previous_at=changes.previous_generated_at,
                 new=changes.new_total, resolved=changes.resolved_total,
                 status_changes=tuple(f"{entry.check_name} {entry.before} → {entry.after_status}" for entry in entries),
                 projects_then=changes.previous_total_projects, projects_now=changes.total_projects)


def build_scorecard(context):
    """The Scorecard of a report, from its finished context (changes folded in)."""
    sections = {section.title: section for section in context.sections}
    actions, more = build_actions(context)
    org_policies = sections["Security & Identity"].org_policies
    org_line = None
    if org_policies is not None and org_policies.compliant < org_policies.total:
        differ = org_policies.total - org_policies.compliant
        org_line = f"{differ} of {org_policies.total} organization policies differ from the recommendation"
    could_not_check = []
    for section in context.sections:
        for item in section.checks:
            if item.status == "Error":
                count = item.details.project_count if item.details is not None else None
                could_not_check.append(item.check_name + (f" ({plural(count, 'project')})" if count else ""))
    coverage = context.coverage
    if coverage:
        coverage_text = f"{coverage.projects_scanned:,} of {coverage.total_projects:,} projects"
    else:
        coverage_text = f"{context.total_projects:,} projects" if context.total_projects else ""
    return Scorecard(
        scope_title=context.scope_title, scope_id=context.scope_id, job_id=context.job_id,
        generated_at=context.generated_at, generated_ts=context.generated_ts, coverage_text=coverage_text,
        stoplights=build_stoplights(context), actions=actions, more_actions=more, org_line=org_line,
        could_not_check=tuple(could_not_check), since=build_since(context.changes),
    )


# --- The exports, built from the same model -------------------------------------------------------------------

def action_plan_csv(card):
    """The action plan: one row per top action, the organization policies as one more, Owner and Target date blank."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(ACTION_PLAN_COLUMNS)
    for action in card.actions:
        writer.writerow([action.rank, action.check_name, action.category, action.status,
                         "" if action.projects is None else action.projects, action.findings,
                         FIX_IN_REPORT if action.fix_in_report else "", "", ""])
    if card.org_line:
        differ = card.org_line.split(" of ")[0]
        writer.writerow(["", ORG_POLICIES_CHECK, STOPLIGHT_OF["Security & Identity"], "Action Required", "", differ, "", "", ""])
    return out.getvalue()


def action_plan_name(card):
    return f"cloudgauge-action-plan-{card.scope_id}-{card.generated_ts[:8]}.csv"


def markdown(card):
    """The page as Markdown, for a document or a chat: header, stoplights, the since line, the actions and their footers."""
    lines = [f"# CloudGauge scorecard — {card.scope_title} {card.scope_id}", ""]
    meta = f"Generated {card.generated_at}"
    if card.since:
        meta += f" · compared with {card.since.previous_at}"
    if card.coverage_text:
        meta += f" · {card.coverage_text}"
    since = card.since
    columns = ["Stoplight", "Category", "Score"] + (["Since last scan"] if since else []) + ["State", "Evidence"]
    lines += [meta, "", "| " + " | ".join(columns) + " |", "|---|---|---:|" + ("---:|" if since else "") + "---|---|"]
    for light in card.stoplights:
        cells = [light.name, light.category, f"{light.score_display}%"] + ([light.delta_display or "—"] if since else []) + [light.state, light.evidence]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    if since:
        line = f"Since the previous scan ({since.previous_at}): {since.new:,} new findings · {since.resolved:,} resolved"
        if since.projects_then and since.projects_then != since.projects_now:
            line += f" · {since.projects_then:,} → {since.projects_now:,} projects"
        line += (" · status changes: " + "; ".join(since.status_changes)) if since.status_changes else " · no status changes"
        lines.append(line + ".")
    else:
        lines.append(f"First scan of this {card.scope_title.lower()} — changes appear from the next scan.")
    columns = ["#", "Check", "Category", "Status", "Projects", "Findings", "Fix in report"] + (["Since last scan"] if since else [])
    lines += ["", "## Top actions", "", "| " + " | ".join(columns) + " |", "|---:|---|---|---|---:|---:|---|" + ("---|" if since else "")]
    for action in card.actions:
        cells = [str(action.rank), action.check_name, action.category, action.status,
                 "—" if action.projects is None else f"{action.projects:,}", f"{action.findings:,}",
                 FIX_IN_REPORT if action.fix_in_report else "—"] + ([action.since or "—"] if since else [])
        lines.append("| " + " | ".join(cells) + " |")
    if card.org_line:
        lines += ["", f"{ORG_POLICIES_CHECK}: {card.org_line}."]
    if card.could_not_check:
        lines += ["", "Could not check: " + ", ".join(card.could_not_check) + "."]
    if card.more_actions:
        lines += ["", f"{plural(card.more_actions, 'more failing check')} on the category pages."]
    return "\n".join(lines) + "\n"


def scorecard_vars(context):
    """The template variables of the page: the model, and the exports the page's buttons hand out."""
    card = build_scorecard(context)
    exports = {"csv": action_plan_csv(card), "csv_name": action_plan_name(card), "markdown": markdown(card)}
    return {"scorecard": card, "scorecard_exports": exports}
