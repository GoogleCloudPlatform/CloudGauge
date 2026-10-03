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
"""How the report lays out a check's table: presentation only, the CSV keeps the raw columns.

Three kinds of rule, applied by ``app.reporting.context.build_details``:

- **Column roles, for every table.** Each column gets a role from its header
  (``COLUMN_ROLES``), or from the look of its values when the header is new
  (``column_role``), and the template renders by role: a *resource* (project,
  principal, instance, rule, bucket...) is a monospace chip, a *resource list*
  is chips with the long tail behind "N more", a *number* is right-aligned
  monospace, a *time* is monospace, a *state* never wraps, and *prose* wraps.
  So every check's table reads the same way, and a new check inherits the
  treatment by naming its columns as the others do.
- **Generic, for every table.** A column whose values are all short never
  wraps, so dates, states, IDs and counts stay on one line when a wide table
  is squeezed (``Cell.nowrap``); the browser collapses the longest cells
  behind "Show more" (``_script.js``).
- **Per check, for the briefings.** ``TABLE_LAYOUTS`` composes fewer, richer
  display columns from the raw ones: a title with a muted second line, two
  stacked lines, a list, a message clamped to three lines, a count that
  discloses its list. The incident row's ten columns become six readable
  ones and the notification row's five become four; the CSV still has every
  raw column.

A ``Fix`` column is never shown as a column: its distinct values become the
finding's remediation block (``fix_lines``), rendered where a Gemini
suggestion would otherwise go, so every failing finding has one remediation
box - exact when the check knows the fix, Gemini's on request when it does not.

Everything a cell holds is in the page as text, so the filter box matches the
projects, locations and message text behind a disclosure too, and a column
sorts by what its cells show first (the title, the start time, the count).
"""
import re
from dataclasses import dataclass

from app.checks import categories

# A column whose values are all at most this long never wraps...
SHORT_VALUE_LENGTH = 20
# ...in a table with at least this many columns (a narrower table is never squeezed).
MIN_COLUMNS_FOR_NOWRAP = 4
# A comma-separated list of up to this many items is shown in full; a longer one is "N items" plus a disclosure.
INLINE_LIST_ITEMS = 3
# Items of a disclosed list included in the page; the CSV has them all.
MAX_DISCLOSED_ITEMS = 200
# Lines of a list cell shown before the rest go behind "N more".
INLINE_LINES = 3
# Distinct fixes shown in a finding's remediation block; the CSV has every row's.
MAX_FIX_LINES = 20
FIX_COLUMN = "Fix"
IN_CSV = "(all in the CSV)"
# A message is clamped to this many lines (the CSS rule in _styles.css); one longer than CLAMP_TOGGLE_LENGTH
# characters, or with that many line breaks, gets the "Show full message" toggle.
CLAMP_LINES = 3
CLAMP_TOGGLE_LENGTH = 160

# Column roles: how a column's cells are rendered (the ``css`` class of the cell, see _macros.html / _design.css).
RESOURCE, RESOURCE_LIST, NUMBER, TIME, STATE, PROSE = "resource", "resource-list", "number", "time", "state", "prose"
COLUMN_ROLES = {
    **dict.fromkeys(("Project", "Project ID", "Instance", "VM", "Cluster", "Node Pool", "Bucket", "Service Account", "Principal", "Member",
                     "Role", "Rule Name", "VPC", "Network", "Subnet", "MIG Name", "Sink Name", "Destination", "Resource", "Resource Name",
                     "Region", "Metric", "ID", "Incident ID", "Policy"), RESOURCE),
    **dict.fromkeys(("Projects", "Project IDs", "Locations", "VMs Not Reporting", "Standalone VMs", "Source Ranges", "Ports"), RESOURCE_LIST),
    **dict.fromkeys(("Rule Count", "Est. Monthly Saving", "Usage", "Retention", "Impacted projects"), NUMBER),
    **dict.fromkeys(("Date", "When (UTC)", "Started", "Ended"), TIME),
    **dict.fromkeys(("Status", "State", "Relevance", "Type", "Finding Type", "Tier", "Category", "Expected Value", "Current Value"), STATE),
    **dict.fromkeys(("Finding", "Issue", "Error", "Reason", "Detail", "Details", "Summary", "Recommendation", "Insight", "Incident",
                     "Notification", "Subject", "Products", "Skipped check", "Missing Categories"), PROSE),
}
# What the items of a resource-list column are called when there are too many to show inline ("37 projects").
LIST_NOUNS = {"Projects": "projects", "Project IDs": "projects", "Locations": "locations", "VMs Not Reporting": "VMs", "Standalone VMs": "VMs",
              "Source Ranges": "ranges", "Ports": "ports"}
# The CSS class a role renders with ("" for prose: the default cell).
ROLE_CSS = {RESOURCE: "code", RESOURCE_LIST: "code", NUMBER: "num", TIME: "time", STATE: "state", PROSE: "prose"}
# Values that look like a number, a percentage or an amount: "12", "1,204", "91.3%", "$412.00", "-3".
NUMBER_VALUE = re.compile(r"^[-+]?[$€£]?\s?\d[\d,]*(\.\d+)?\s?%?$")
# Values that look like an identifier: no spaces, and a separator an ID has or digits only.
ID_VALUE = re.compile(r"^(?:\S*[/@:.\-_]\S*|\d+)$")


@dataclass(frozen=True)
class Cell:
    """What the template renders in one ``<td>``.

    ``kind`` is one of:

    - ``text``: ``text``, on one line when ``nowrap``;
    - ``chips``: ``lines`` as resource chips, inline when there are a few; ``text``
      holds the summary ("37 projects") that discloses them when there are many,
      and ``body`` a tail line ("... and 12 more (all in the CSV)");
    - ``stack``: ``lines`` one under the other, the first normal and the rest muted;
    - ``rich``: a ``text`` title and a muted ``secondary`` line, optionally
      ending in a ``more`` disclosure (``(summary, body)``) and a monospace
      ``code`` token (an ID);
    - ``disclose``: a ``text`` summary ("37 projects") that opens to ``body``;
    - ``list``: ``lines`` as a bulleted list; ``more`` holds the rest as
      ``("N more", (line, ...))`` when there are more than ``INLINE_LINES``;
    - ``article``: a ``text`` title over a ``body`` clamped to three lines;
      ``more`` holds the toggle's labels when the body is long enough to need one.

    ``css`` is the column's role class (``ROLE_CSS``) and/or a cell's own class.
    """
    kind: str = "text"
    text: str = ""
    lines: tuple = ()
    body: str = ""
    secondary: str = ""
    more: tuple | None = None
    code: str = ""
    nowrap: bool = False
    css: str = ""

    @property
    def classes(self):
        """The ``<td>`` class attribute: ``nowrap`` and/or ``css``, or empty."""
        return " ".join(name for name in ("nowrap" if self.nowrap else "", self.css) if name)


def column_role(header, values=()):
    """The role of a column: by its header, else by what its non-empty values look like.

    Unknown headers: all identifiers (no spaces, with a separator) → ``RESOURCE``;
    all numbers → ``NUMBER``; otherwise ``PROSE``. A column with no values is prose.
    """
    role = COLUMN_ROLES.get(header)
    if role:
        return role
    present = [str(v).strip() for v in values if str(v).strip()]
    if not present:
        return PROSE
    if all(NUMBER_VALUE.match(v) for v in present):
        return NUMBER
    if all(ID_VALUE.match(v) for v in present):
        return RESOURCE
    return PROSE


def chips(items, noun="items"):
    """A ``chips`` cell: a few items inline; many behind "37 projects" (the first ``MAX_DISCLOSED_ITEMS`` in the page)."""
    items = tuple(items)
    if len(items) <= INLINE_LIST_ITEMS:
        return Cell("chips", lines=items, css=ROLE_CSS[RESOURCE_LIST])
    shown = items[:MAX_DISCLOSED_ITEMS]
    tail = f"… and {len(items) - len(shown):,} more {IN_CSV}" if len(items) > len(shown) else ""
    return Cell("chips", text=f"{len(items):,} {noun}", lines=shown, body=tail, css=ROLE_CSS[RESOURCE_LIST])


def role_cell(role, value, header=None, nowrap=False):
    """The cell of one raw ``value`` in a column with ``role``."""
    text = f"{value}"
    if role == RESOURCE_LIST:
        return chips(split_items(text), LIST_NOUNS.get(header, "items"))
    return Cell("text", text, nowrap=nowrap or role in (RESOURCE, NUMBER, TIME, STATE) and len(text) <= SHORT_VALUE_LENGTH * 2,
                css=ROLE_CSS[role])


def split_items(text):
    """The items of a comma-separated cell (``"a, b, c"``); empty for an empty cell."""
    return [part.strip() for part in str(text or "").split(",") if part.strip()]


def counted(items, noun):
    """A short list as text; a long one as a ``disclose`` cell: "37 projects" opening to the list."""
    if len(items) <= INLINE_LIST_ITEMS:
        return Cell("text", ", ".join(items))
    shown = items[:MAX_DISCLOSED_ITEMS]
    body = ", ".join(shown)
    if len(items) > len(shown):
        body += f" … and {len(items) - len(shown):,} more {IN_CSV}"
    return Cell("disclose", text=f"{len(items):,} {noun}", body=body)


def listed(lines):
    """A ``list`` cell: the first ``INLINE_LINES`` lines shown, the rest behind "N more"."""
    lines = tuple(line for line in lines if line.strip())
    rest = lines[INLINE_LINES:]
    return Cell("list", lines=lines[:INLINE_LINES], more=(f"{len(rest)} more", rest) if rest else None)


def article(title, body):
    """An ``article`` cell: ``title`` over ``body``, with a "Show full message" toggle when the body may be clamped."""
    body = str(body or "")
    long = len(body) > CLAMP_TOGGLE_LENGTH or body.count("\n") >= CLAMP_LINES
    return Cell("article", text=title, body=body, more=("Show full message", "Show less") if long else None)


def _text(row, column, **kwargs):
    return Cell("text", f"{row.get(column, '')}", **kwargs)


def incident_cells(row):
    """The six display cells of a Service Health Incidents row (``app.checks.service_health.incident_row``).

    The incident ID rides on the title's second line (after the locations) rather
    than in a column of its own, so the table fits a laptop screen without a
    sideways scroll; it is still in the page for the filter box and for copying.
    """
    started, ended = f"{row.get(categories.INCIDENT_STARTED, '')}", f"{row.get('Ended', '')}"
    when = Cell("stack", lines=(started or "—", f"→ {ended}" if ended else "→ ongoing"), nowrap=True, css=ROLE_CSS[TIME])
    locations = counted(split_items(row.get("Locations")), "locations")
    incident = Cell("rich", text=f"{row.get('Incident', '')}",
                    secondary=locations.text if locations.kind == "text" else "",
                    more=(locations.text, locations.body) if locations.kind == "disclose" else None,
                    code=f"{row.get(categories.INCIDENT_ID, '')}", css=ROLE_CSS[PROSE])
    return (
        _text(row, categories.INCIDENT_STATE, nowrap=True, css="state state-active" if categories.is_active_incident(row) else "state"),
        when,
        incident,
        _text(row, "Products", css=ROLE_CSS[PROSE]),
        chips(split_items(row.get(categories.INCIDENT_PROJECTS)), "projects"),
        _text(row, categories.INCIDENT_RELEVANCE, nowrap=True, css=ROLE_CSS[STATE]),
    )


INCIDENT_HEADERS = ("State", "When (UTC)", "Incident", "Products", "Projects", "Relevance")
INCIDENT_COLUMNS = (categories.INCIDENT_ID, "Incident", categories.INCIDENT_STARTED)


def incident_layout(headers, rows):
    """``(display headers, rows of cells)`` for incident rows; ``None`` for a note or error table."""
    if not set(INCIDENT_COLUMNS) <= set(headers):
        return None
    return INCIDENT_HEADERS, tuple(incident_cells(row) for row in rows)


def notification_cells(row, with_projects=False):
    """The display cells of an Advisory Notifications row (``app.checks.advisories.notification_row``)."""
    cells = [
        _text(row, categories.ADVISORY_DATE, nowrap=True, css=ROLE_CSS[TIME]),
        _text(row, categories.ADVISORY_TYPE, css=ROLE_CSS[STATE]),
        article(f"{row.get(categories.ADVISORY_SUBJECT, '')}", row.get("Summary", "")),
        listed(f"{row.get('Details', '')}".split("\n")),
    ]
    if with_projects:
        cells.append(chips(split_items(row.get(categories.ADVISORY_PROJECTS)), "projects"))
    return tuple(cells)


NOTIFICATION_HEADERS = ("Date", "Type", "Notification", "Details")
NOTIFICATION_COLUMNS = (categories.ADVISORY_SUBJECT, categories.ADVISORY_DATE, categories.ADVISORY_TYPE)


def notification_layout(headers, rows):
    """``(display headers, rows of cells)`` for notification rows; ``None`` for a note or error table."""
    if not set(NOTIFICATION_COLUMNS) <= set(headers):
        return None
    with_projects = categories.ADVISORY_PROJECTS in headers
    display = NOTIFICATION_HEADERS + ((categories.ADVISORY_PROJECTS,) if with_projects else ())
    return display, tuple(notification_cells(row, with_projects) for row in rows)


TABLE_LAYOUTS = {"Service Health Incidents": incident_layout, "Advisory Notifications": notification_layout}


def column_roles(headers, rows):
    """The role of each column of a table (``column_role`` of its header and values)."""
    return tuple(column_role(header, (row[i] for row in rows)) for i, header in enumerate(headers))


def generic_layout(headers, rows):
    """``(display headers, rows of cells)`` for any table: every column rendered by its role, short columns on one line."""
    roles = column_roles(headers, rows)
    wide = len(headers) >= MIN_COLUMNS_FOR_NOWRAP
    short = [wide and all(len(row[i]) <= SHORT_VALUE_LENGTH for row in rows) for i in range(len(headers))]
    return tuple(headers), tuple(tuple(role_cell(roles[i], value, headers[i], nowrap=short[i]) for i, value in enumerate(row)) for row in rows)


def fix_lines(headers, rows):
    """The distinct values of the ``Fix`` column, in row order, capped at ``MAX_FIX_LINES`` with a tail line."""
    if FIX_COLUMN not in headers:
        return ()
    index = list(headers).index(FIX_COLUMN)
    distinct = list(dict.fromkeys(row[index] for row in rows if row[index]))
    if len(distinct) > MAX_FIX_LINES:
        distinct = distinct[:MAX_FIX_LINES] + [f"… and {len(distinct) - MAX_FIX_LINES:,} more {IN_CSV}"]
    return tuple(distinct)


def without_column(headers, rows, column):
    """``headers`` and ``rows`` without ``column`` (unchanged when it is absent)."""
    if column not in headers:
        return tuple(headers), tuple(tuple(row) for row in rows)
    index = list(headers).index(column)
    return (tuple(h for i, h in enumerate(headers) if i != index),
            tuple(tuple(v for i, v in enumerate(row) if i != index) for row in rows))


def lay_out(check_name, headers, rows, row_dicts):
    """The display headers, rows of cells and fix lines of a check's table.

    ``headers``/``rows`` are the raw strings (``row_dicts`` the raw dicts, for
    the per-check layouts). A per-check layout applies when the table has its
    columns; otherwise the generic one does, without the ``Fix`` column.
    """
    fixes = fix_lines(headers, rows)
    layout = TABLE_LAYOUTS.get(check_name)
    laid_out = layout(headers, row_dicts) if layout else None
    if laid_out is None:
        laid_out = generic_layout(*without_column(headers, rows, FIX_COLUMN))
    display_headers, cells = laid_out
    return display_headers, cells, fixes
