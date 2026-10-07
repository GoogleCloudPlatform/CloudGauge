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
"""Changes since the previous scan of the same scope.

A finished scan leaves a *summary* behind (``summarize``): a small JSON document
with its scores, counts, each check's status and, for the checks that need
work, the identity of every row. The results store files it under
``scopes/<scope>/<scope id>/`` (``GcsResultsStore.write_scan_summary``), so the
next scan of the same scope finds its predecessor with one listing
(``read_previous_summary``) and ``compare`` turns the two summaries into what
the report shows: the *Previous scan* line in the header, the *Changes since
last scan* card on the Overview, a chip on every check whose rows changed, a
*New* marker on rows the previous scan did not have, and the resolved rows
listed under the table.

What counts as the same finding across two scans is its **identity**: the
check's row with the columns that only measure (numbers, dates) and the
``Fix`` and ``Version`` columns left out, and the digits inside prose cells
normalised, so a recommender that re-estimates a saving or rewords "taken 4
times" does not produce a new finding, and a GKE node pool that takes a patch
while it stays on an unsupported minor is still the same one. Identities are
counted: the second identical row is ``"… #2"``, so two identical rows stay
two findings. Only Action Required and Investigation Recommended checks carry
identities; a check that is Compliant has nothing to list, an Error check
could not look, and the briefings (Informational) are events, not findings,
and are never compared.

The rules of ``compare``, per check:

- in both scans, neither an Error: ``+N new`` / ``−M resolved`` by identity, and
  the status change if there is one (Compliant → Action Required lists every
  row as new; the reverse lists every previous row as resolved);
- in both scans, one of them an Error: the status change only — the rows are
  *not compared* (an Error scan did not look, so nothing was resolved);
- in both scans, but the check's rows cannot be compared across a release
  after the one that wrote the previous summary (``RESHAPED_CHECKS``: the rows
  changed shape, or the rule changed): the status change only — the rows are
  *not compared (rows changed)* or *not compared (rule changed)*, since every
  row would read as new and every old one as resolved, or a snapshot nobody
  touched would read as fixed; the next scan compares as usual;
- only in this scan, both scans by the same release (v15.5): the previous scan
  had nothing to check — an empty folder that has its first project now — so
  every row is new (the card says ``no result → Action Required``);
- only in this scan, the previous scan by another release or one that predates
  ``release``: *not compared (new check)*, never "all new";
- only in the previous scan: listed once on the card — "No result in this
  scan" within a release, "No longer checked" across releases — and nothing is
  resolved by it.

Scores and counts are not read from the previous summary but **recomputed
from its check statuses under the current rule** (``app.reporting.scoring``):
a summary keeps every check's status and the policy counts, which is all the
rule needs, so a scan made under an older rule compares like with like and a
change of rule never shows as a change of posture. The summary still records
the scores it was rendered with, for anyone reading the JSON.
"""
import re
from collections import Counter
from dataclasses import dataclass, field

from app.config import VERSION
from app.reporting.layouts import FIX_COLUMN, NUMBER, PROSE, TIME, column_roles
from app.reporting.scoring import NOT_ASSESSED_TEXT, overview_from_checks, scores_from_checks

# 2 (v15.2): the Organization Policies entry carries ``policies: {compliant, total}``; scores may be null (not assessed).
# 3 (v15.5): ``release`` names the version that wrote the summary; without it (older summaries) a check only in the
#            current scan is a new check.
SUMMARY_VERSION = 3
# Cells of one identity are joined with this; the N-th duplicate gets " #N".
IDENTITY_SEPARATOR = " · "
# Statuses whose rows are compared; the others carry no identities (see the module docstring).
COMPARED_STATUSES = ("Action Required", "Investigation Recommended")
NOT_COMPARED = "not compared"
# The "before" of a check the previous scan of the same release had no result for.
NO_RESULT = "no result"
# The card's footer naming the checks only the previous scan had: within a release, across releases.
NO_RESULT_NOW = "No result in this scan"
NO_LONGER_CHECKED = "No longer checked"
# How many resolved rows a check lists under its table; the summary keeps them all.
MAX_LISTED_RESOLVED = 100
# How many status changes the Changes card shows per category before "N more".
INLINE_STATUS_CHANGES = 3
# Organization Policies is summarised as a check of this name (identities: the policies that differ).
ORG_POLICIES_CHECK = "Organization Policies"
# Columns that never enter an identity: the fix is derived from the row, and a version is a measurement
# of its component (GKE Supported Versions), not what the finding is about.
EXCLUDED_COLUMNS = (FIX_COLUMN, "Version")
# Checks whose rows cannot be compared with a previous scan by an older release → (the release that drew the line,
# why). Against such a scan the rows are not compared (module docstring); the status still is. The reasons:
ROWS_CHANGED = "rows changed"  # the rows changed shape, and with them every row's identity
RULE_CHANGED = "rule changed"  # the rule changed: a row that vanished was not fixed, one that appeared is not new
RESHAPED_CHECKS = {
    # v15.6: one row counting the snapshots → one row per single-region snapshot (rows changed);
    # v16.1: a snapshot in a multi-region passes (rule changed). The newest line is the one that matters.
    "Disk Snapshot Resilience": ("16.1", RULE_CHANGED),
}

DIGITS = re.compile(r"\d[\d,]*(?:\.\d+)?")
MINUS = "\u2212"  # a real minus sign, as wide as the plus


def normalize_prose(text):
    """``"Save $12.34/month"`` → ``"Save $#/month"``: prose compares without its numbers."""
    return DIGITS.sub("#", text)


class RowIdentities:
    """Builds the identities of a check's rows, in order, numbering duplicates.

    ``headers`` are the check's columns and ``roles`` their layout roles
    (``app.reporting.layouts.column_roles``); numbers, times and the
    ``EXCLUDED_COLUMNS`` are left out of the identity, prose cells lose their digits.
    """

    def __init__(self, headers, roles):
        self.headers = tuple(headers)
        self.kept = tuple(i for i, (header, role) in enumerate(zip(headers, roles))
                          if role not in (NUMBER, TIME) and header not in EXCLUDED_COLUMNS)
        self.prose = frozenset(i for i in self.kept if roles[i] == PROSE)
        self.seen = Counter()

    def next(self, values):
        """The identity of the next row (``values`` aligned with ``headers``, as strings)."""
        parts = []
        for i in self.kept:
            value = str(values[i]).strip()
            parts.append(normalize_prose(value) if i in self.prose else value)
        identity = IDENTITY_SEPARATOR.join(parts)
        self.seen[identity] += 1
        count = self.seen[identity]
        return identity if count == 1 else f"{identity} #{count}"

    def next_dict(self, row):
        """The identity of the next row given as a dict (missing columns count as empty)."""
        return self.next([row.get(header, "") for header in self.headers])


def identities_for(headers, rows):
    """``(roles, identities)`` of a check's rows (strings aligned with ``headers``), in row order."""
    roles = column_roles(headers, rows)
    builder = RowIdentities(headers, roles)
    return roles, tuple(builder.next(row) for row in rows)


TEXT_HEADERS = ("Finding",)  # a check whose details are lines of text: each line is one prose cell


def text_identities(lines):
    """The identities of a check's text lines, in order: the line with its digits normalised, duplicates numbered."""
    builder = RowIdentities(TEXT_HEADERS, (PROSE,))
    return tuple(builder.next((line,)) for line in lines)


@dataclass(frozen=True)
class RowMatcher:
    """Which of a check's rows are new, for the CSV: rebuilds the identities in the CSV's row order."""
    headers: tuple
    roles: tuple
    new: frozenset

    def tracker(self):
        """A fresh identity builder; feed it the check's rows in order and ask ``is_new``."""
        matcher = self

        class Tracker(RowIdentities):
            def is_new(self, row):
                return self.next_dict(row) in matcher.new
        return Tracker(self.headers, self.roles)


@dataclass(frozen=True)
class CheckChange:
    """What changed for one check since the previous scan (``None`` on a check that is not compared at all)."""
    new: int = 0
    resolved: int = 0
    previous_status: str | None = None  # set when it differs from the current status
    note: str | None = None  # NOT_COMPARED, with the reason in ``note_reason``
    note_reason: str | None = None  # "new check", "could not be checked then", "could not be checked now", "rows changed", "rule changed"
    new_identities: frozenset = frozenset()
    resolved_items: tuple = ()  # the resolved identities, in the previous scan's order, capped at MAX_LISTED_RESOLVED
    resolved_omitted: int = 0  # how many more than ``resolved_items`` lists
    first_result: bool = False  # the previous scan, by the same release, had no result for the check: nothing to check then

    @property
    def chip(self):
        """The chip next to the check's name: ``"+3 new · −5 resolved"``, ``"not compared"``, or ``None`` when nothing changed."""
        if self.note:
            return self.note
        parts = []
        if self.new:
            parts.append(f"+{self.new:,} new")
        if self.resolved:
            parts.append(f"{MINUS}{self.resolved:,} resolved")
        return " · ".join(parts) or None

    @property
    def chip_title(self):
        """The chip's tooltip: the status change and why rows were not compared."""
        bits = []
        if self.previous_status:
            bits.append(f"Was {self.previous_status} in the previous scan")
        if self.first_result:
            bits.append("No result in the previous scan (nothing to check then), so every finding is new")
        if self.note_reason:
            bits.append(f"Rows {self.note}: {self.note_reason}")
        return "; ".join(bits) or "Compared with the previous scan of this scope"


@dataclass(frozen=True)
class ChangeEntry:
    """One line of the card's *Status changes* column: ``before → after``, or a note when ``before`` is None."""
    check_name: str
    slug: str  # the check's anchor within its section
    after: str  # the current status, with the note when the rows were not compared ("Compliant · not compared (…)"), or the note alone
    before: str | None = None  # the previous status

    @property
    def after_status(self):
        """The current status alone (``"Compliant"`` for ``"Compliant · not compared (…)"``): what sorts and what a one-line summary says."""
        return self.after.split(" · ", 1)[0]


@dataclass(frozen=True)
class CategoryChange:
    category_name: str
    section_id: str
    score_display: str  # "55"; empty when this scan did not assess the category
    previous_score_display: str | None  # "40", NOT_ASSESSED_TEXT, or None when the previous scan had no such category
    delta_display: str  # "+6", "−11", or "—" for no change (also "—" when either side has no score)
    delta_class: str  # "up", "down", or "flat"
    resolved: int
    new: int
    entries: tuple = ()  # ChangeEntry: the status changes first, then the notes, in display order

    @property
    def score_text(self):
        """``"55%"`` or ``"Not assessed"``: the card's score cell."""
        return f"{self.score_display}%" if self.score_display else NOT_ASSESSED_TEXT


@dataclass(frozen=True)
class Changes:
    """The *Changes since last scan* view-model (``None`` in the context when there is no previous scan)."""
    previous_job_id: str
    previous_generated_at: str
    previous_total_projects: int | None
    total_projects: int | None
    categories: tuple
    overview_deltas: dict  # Overview field name → current minus previous
    new_total: int
    resolved_total: int
    retired_checks: tuple = ()  # checks the previous scan had and this one does not
    retired_label: str = NO_LONGER_CHECKED  # NO_RESULT_NOW when both scans are by the same release (nothing to check now)
    checks: dict = field(default_factory=dict)  # check name → CheckChange (for the chips and row markers)

    @property
    def population(self):
        """``"3 projects"`` or ``"3 projects then · 4 now"`` when the scope's size changed."""
        then, now = self.previous_total_projects, self.total_projects
        if then is None or now is None:
            return ""
        if then == now:
            return f"{now:,} project{'' if now == 1 else 's'}"
        return f"{then:,} project{'' if then == 1 else 's'} then · {now:,} now"


def count_delta(value):
    """``+6`` / ``−11`` / ``—`` for an integer difference."""
    if value > 0:
        return f"+{value:,}"
    if value < 0:
        return f"{MINUS}{-value:,}"
    return "\u2014"


def delta_class(value):
    return "up" if value > 0 else "down" if value < 0 else "flat"


def check_change(current, previous):
    """``CheckChange`` for a check in both scans (summary entries), or ``None`` for a briefing."""
    status, previous_status = current["status"], previous["status"]
    if status == "Informational" or previous_status == "Informational":
        return None
    changed = previous_status if previous_status != status else None
    if "Error" in (status, previous_status):
        reason = "could not be checked now" if status == "Error" else "could not be checked then"
        if status == "Error" and previous_status == "Error":
            reason = "could not be checked in either scan"
        return CheckChange(previous_status=changed, note=NOT_COMPARED, note_reason=reason)
    now, then = current.get("identities", []), previous.get("identities", [])
    now_set, then_set = frozenset(now), frozenset(then)
    new = frozenset(identity for identity in now if identity not in then_set)
    resolved = [identity for identity in then if identity not in now_set]
    return CheckChange(
        new=len(new), resolved=len(resolved), previous_status=changed, new_identities=new,
        resolved_items=tuple(resolved[:MAX_LISTED_RESOLVED]), resolved_omitted=max(0, len(resolved) - MAX_LISTED_RESOLVED),
    )


def first_result_change(current):
    """``CheckChange`` for a check the previous scan had no result for, both scans by the same release.

    The release could have run the check then and did not, so there was nothing to check (an empty folder
    with its first project now): every row that needs work is new. An Error now is still not compared.
    """
    if current["status"] == "Error":
        return CheckChange(note=NOT_COMPARED, note_reason="could not be checked now")
    new = frozenset(current.get("identities", []))
    return CheckChange(new=len(new), new_identities=new, first_result=True)


def same_release(previous, current):
    """Whether both summaries name the same release (older summaries name none, and compare across releases)."""
    return bool(previous.get("release")) and previous.get("release") == current.get("release")


def release_tuple(release):
    """``"15.6"`` → ``(15, 6)`` for ordering releases; ``None`` or ``""`` (a summary older than v15.5) → ``()``, before every release."""
    return tuple(int(part) for part in re.findall(r"\d+", release or ""))


def rows_reshaped_since(name, previous):
    """Why check ``name``'s rows cannot be compared with the scan ``previous`` (``RESHAPED_CHECKS``: the release that
    drew the line is newer than the one that wrote ``previous``), or ``None`` when they compare as usual."""
    line = RESHAPED_CHECKS.get(name)
    if line and release_tuple(previous.get("release")) < release_tuple(line[0]):
        return line[1]
    return None


def reshaped_change(current, previous, reason=ROWS_CHANGED):
    """``CheckChange`` for a check whose rows cannot be compared with the previous scan's (``reason``: why): the status
    change if there is one, the rows *not compared*. A briefing stays ``None`` and an Error on either side keeps its
    own reason (its rows are not compared anyway)."""
    change = check_change(current, previous)
    if change is None or change.note:
        return change
    return CheckChange(previous_status=change.previous_status, note=NOT_COMPARED, note_reason=reason)


def compare(previous, current, slugs, section_ids):
    """The ``Changes`` between two summaries (``previous`` may be ``None``: no previous scan, returns ``None``).

    ``slugs`` maps check names to their anchors and ``section_ids`` category
    names to their section ids (both from the report context).
    """
    if not previous:
        return None
    prev_checks, cur_checks = previous.get("checks", {}), current.get("checks", {})
    within_release = same_release(previous, current)
    checks = {}
    for name, entry in cur_checks.items():
        if entry["status"] == "Informational":
            continue
        reason = rows_reshaped_since(name, previous) if name in prev_checks else None
        if reason:
            change = reshaped_change(entry, prev_checks[name], reason)
        elif name in prev_checks:
            change = check_change(entry, prev_checks[name])
        elif within_release:
            change = first_result_change(entry)
        else:
            change = CheckChange(note=NOT_COMPARED, note_reason="new check")
        if change is not None:
            checks[name] = change
    retired = tuple(sorted(name for name, entry in prev_checks.items()
                           if name not in cur_checks and entry["status"] != "Informational"))

    # The previous scan under the current rule (module docstring): its scores and counts come from its checks.
    previous_scores = scores_from_checks(prev_checks)
    previous_categories = previous.get("scores", {})
    categories = []
    for category_name, score in current.get("scores", {}).items():
        if category_name in previous_categories:
            previous_score = previous_scores.get(category_name)  # None: not assessed then
            previous_display = NOT_ASSESSED_TEXT if previous_score is None else f"{previous_score:.0f}"
        else:
            previous_score, previous_display = None, None  # the previous scan had no such category
        compared = score is not None and previous_score is not None
        delta = round(score) - round(previous_score) if compared else 0
        names = [name for name, entry in cur_checks.items() if entry.get("category") == category_name and name in checks]
        entries = []
        for name in names:  # status changes first...
            change = checks[name]
            if change.previous_status:
                note = f" · {change.note} ({change.note_reason})" if change.note else ""
                entries.append(ChangeEntry(name, slugs.get(name, ""), cur_checks[name]["status"] + note, change.previous_status))
        for name in names:  # ...then the checks that need work and had no result in the previous scan...
            change = checks[name]
            if change.first_result and cur_checks[name]["status"] in COMPARED_STATUSES:
                entries.append(ChangeEntry(name, slugs.get(name, ""), cur_checks[name]["status"], NO_RESULT))
        for name in names:  # ...then the checks whose rows could not be compared
            change = checks[name]
            if change.note and not change.previous_status:
                entries.append(ChangeEntry(name, slugs.get(name, ""), f"{change.note} ({change.note_reason})"))
        categories.append(CategoryChange(
            category_name=category_name, section_id=section_ids.get(category_name, ""),
            score_display="" if score is None else f"{score:.0f}", previous_score_display=previous_display,
            delta_display=count_delta(delta) if compared else "\u2014", delta_class=delta_class(delta),
            resolved=sum(checks[name].resolved for name in names), new=sum(checks[name].new for name in names),
            entries=tuple(entries),
        ))

    previous_overview = overview_from_checks(prev_checks)
    overview_deltas = {key: current["overview"].get(key, 0) - previous_overview.get(key, 0)
                       for key in current.get("overview", {})}
    return Changes(
        previous_job_id=previous["job_id"], previous_generated_at=previous.get("generated_at", ""),
        previous_total_projects=previous.get("total_projects"), total_projects=current.get("total_projects"),
        categories=tuple(categories), overview_deltas=overview_deltas,
        new_total=sum(c.new for c in checks.values()), resolved_total=sum(c.resolved for c in checks.values()),
        retired_checks=retired, retired_label=NO_RESULT_NOW if within_release else NO_LONGER_CHECKED, checks=checks,
    )


def summarize(context):
    """The summary of a rendered report (a JSON-ready dict), from its ``ReportContext``.

    Identities come from every row of a check (``Details.identities``), not only
    the rows the page shows. Organization Policies is summarised as a check whose
    identities are the policies that differ from the recommended value, with the
    counts behind its share of the score (``policies``).
    """
    checks = {}
    for section in context.sections:
        for check in section.checks:
            entry = {"category": section.title, "status": check.status,
                     "rows": check.details.total_rows if check.details is not None else 0}
            if check.status in COMPARED_STATUSES and check.details is not None:
                entry["identities"] = list(check.details.identities)
            checks[check.check_name] = entry
        if section.org_policies is not None:
            policies = section.org_policies
            differing = [f"{category.name}{IDENTITY_SEPARATOR}{row.display_name}" for category in policies.categories
                         for row in category.rows if row.status != "Compliant"]
            checks[ORG_POLICIES_CHECK] = {"category": section.title, "status": "Action Required" if differing else "Compliant",
                                          "rows": policies.total, "identities": differing,
                                          "policies": {"compliant": policies.compliant, "total": policies.total}}
    overview = context.overview
    return {
        "version": SUMMARY_VERSION, "release": VERSION, "job_id": context.job_id, "scope": context.scope, "scope_id": context.scope_id,
        "generated_at": context.generated_at, "generated_ts": context.generated_ts,
        "total_projects": context.total_projects,
        "requested_by": context.requested_by,  # None: unknown (not behind IAP)
        "overview": {"action_count": overview.action_count, "investigation_count": overview.investigation_count,
                     "compliant_count": overview.compliant_count, "error_count": overview.error_count},
        "scores": {row.category_name: row.score for row in context.score_summary},  # None: not assessed
        "checks": checks,
    }
