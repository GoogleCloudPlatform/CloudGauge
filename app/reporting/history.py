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
"""The history page (v17): a scope's scans over time, from the summaries under ``scopes/``.

``build_history(scope, scope_id, summaries)`` turns the scope's scan summaries
(``app.reporting.changes.summarize``, newest first) into what ``history.html``
lays out: one :class:`HistoryEntry` per scan — when, by which release, who
asked, how many projects, the four pillar scores and the four Overview counts,
and the checks whose status changed since the scan before it — and a
:class:`HistoryChart`, the pillar scores over time as inline SVG polylines (no
script, no library: the page is a document). Scores are not read from the
summaries but recomputed from their check statuses under the current rule
(``app.reporting.scoring``), as *Changes since last scan* does, so a change
of rule never draws as a change of posture.
"""
from dataclasses import dataclass, replace

from app.reporting.scorecard import PILLARS
from app.reporting.scoring import NOT_ASSESSED_TEXT, overview_from_checks, scores_from_checks

# The chart's drawing area (SVG user units): the pillar lines run across it, left (oldest) to right (newest).
CHART_WIDTH, CHART_HEIGHT = 720, 220
CHART_PADDING = {"left": 36, "right": 90, "top": 12, "bottom": 28}
# The lines read in monochrome, like the Scorecard's stoplights: one dash pattern per pillar.
DASHES = {"Stability": "", "Security": "6 4", "Operations": "2 3", "Efficiency": "10 3 2 3"}
# How many status changes a scan's row lists before "N more".
INLINE_FLIPS = 3


@dataclass(frozen=True)
class HistoryEntry:
    job_id: str
    generated_at: str  # "2026-10-03 20:11 UTC"
    release: str
    requested_by: str  # "" when unknown
    total_projects: int | None
    scores: dict  # pillar name -> score (None when not assessed)
    action_count: int
    investigation_count: int
    compliant_count: int
    error_count: int
    flips: tuple  # "Open Firewall Rules: Compliant → Action Required", since the scan before this one
    first: bool  # the scope's first scan on record

    def score_text(self, pillar):
        score = self.scores.get(pillar)
        return NOT_ASSESSED_TEXT if score is None else f"{score:.0f}%"

    def score_class(self, pillar):
        score = self.scores.get(pillar)
        return "none" if score is None else "high" if score > 90 else "medium" if score > 70 else "low"

    @property
    def inline_flips(self):
        return self.flips[:INLINE_FLIPS]

    @property
    def more_flips(self):
        return max(0, len(self.flips) - INLINE_FLIPS)


@dataclass(frozen=True)
class ChartLine:
    pillar: str
    dash: str
    points: str  # the SVG polyline's points attribute; "" when the pillar was never assessed
    last_x: float | None  # where the line ends: the label sits there
    last_y: float | None
    last_text: str  # "80%" or "—"
    label_y: float | None = None  # where the label is drawn: last_y, nudged apart from the labels of lines that end together


@dataclass(frozen=True)
class HistoryChart:
    width: int
    height: int
    lines: tuple  # ChartLine, one per pillar
    ticks: tuple  # (y, label) for 0, 50 and 100
    labels: tuple  # (x, text): the oldest and newest scan's dates under the axis
    scans: int

    @property
    def view_box(self):
        return f"0 0 {self.width} {self.height}"


@dataclass(frozen=True)
class History:
    scope: str
    scope_id: str
    scope_title: str
    entries: tuple  # HistoryEntry, newest first
    chart: HistoryChart | None  # None without a scan
    pillars: tuple  # the pillar names, in Scorecard order

    @property
    def count(self):
        return len(self.entries)

    @property
    def span_text(self):
        """``"12 scans, 2026-07-01 to 2026-10-03"`` (the header's second line); empty without a scan."""
        if not self.entries:
            return ""
        if self.count == 1:
            return f"1 scan, {self.entries[0].generated_at}"
        return f"{self.count} scans, {self.entries[-1].generated_at[:10]} to {self.entries[0].generated_at[:10]}"


def pillar_scores(summary):
    """Pillar name -> score under the current rule, from a summary's check statuses (``None``: not assessed)."""
    by_category = scores_from_checks(summary.get("checks") or {})
    return {pillar: by_category.get(category) for pillar, category in PILLARS}


def status_flips(current, previous):
    """The checks whose status differs between two summaries, worst change first: ``"Check: before → after"``.

    Briefings (Informational) are events, not findings, and stay out; a check only one scan has is not a flip.
    """
    if previous is None:
        return ()
    rank = {"Action Required": 0, "Investigation Recommended": 1, "Error": 2, "Compliant": 3}
    flips = []
    now, then = current.get("checks") or {}, previous.get("checks") or {}
    for name, entry in now.items():
        before = then.get(name)
        after_status = entry.get("status")
        if before is None or after_status == before.get("status") or "Informational" in (after_status, before.get("status")):
            continue
        flips.append((rank.get(after_status, 4) >= rank.get(before.get("status"), 4), rank.get(after_status, 4), name,
                      f"{name}: {before.get('status')} → {after_status}"))
    flips.sort()
    return tuple(text for _, _, _, text in flips)


def build_entries(summaries):
    """One :class:`HistoryEntry` per summary (given newest first), each compared with the one before it."""
    entries = []
    for index, summary in enumerate(summaries):
        previous = summaries[index + 1] if index + 1 < len(summaries) else None
        counts = overview_from_checks(summary.get("checks") or {})
        entries.append(HistoryEntry(
            job_id=summary.get("job_id", ""), generated_at=summary.get("generated_at", ""), release=str(summary.get("release") or ""),
            requested_by=summary.get("requested_by") or "", total_projects=summary.get("total_projects"),
            scores=pillar_scores(summary), action_count=counts["action_count"], investigation_count=counts["investigation_count"],
            compliant_count=counts["compliant_count"], error_count=counts["error_count"],
            flips=status_flips(summary, previous), first=previous is None,
        ))
    return tuple(entries)


def build_chart(entries):
    """The pillar lines over the entries (newest first in, oldest left on the chart); ``None`` without an entry."""
    if not entries:
        return None
    oldest_first = list(reversed(entries))
    left, right = CHART_PADDING["left"], CHART_WIDTH - CHART_PADDING["right"]
    top, bottom = CHART_PADDING["top"], CHART_HEIGHT - CHART_PADDING["bottom"]
    count = len(oldest_first)

    def x_of(index):
        return float(left) if count == 1 else left + (right - left) * index / (count - 1)

    def y_of(score):
        return bottom - (bottom - top) * score / 100

    lines = []
    for pillar, _ in PILLARS:
        points, last = [], None
        for index, entry in enumerate(oldest_first):
            score = entry.scores.get(pillar)
            if score is None:
                continue
            x, y = round(x_of(index), 1), round(y_of(score), 1)
            points.append(f"{x},{y}")
            last = (x, y, f"{score:.0f}%")
        lines.append(ChartLine(pillar=pillar, dash=DASHES.get(pillar, ""), points=" ".join(points),
                               last_x=last[0] if last else None, last_y=last[1] if last else None, last_text=last[2] if last else "\u2014"))
    ticks = tuple((round(y_of(value), 1), f"{value}") for value in (0, 50, 100))
    labels = [(round(x_of(0), 1), oldest_first[0].generated_at[:10])]
    if count > 1:
        labels.append((round(x_of(count - 1), 1), oldest_first[-1].generated_at[:10]))
    return HistoryChart(width=CHART_WIDTH, height=CHART_HEIGHT, lines=tuple(spread_labels(lines)), ticks=ticks, labels=tuple(labels), scans=count)


# Two end labels closer than this (SVG units) are nudged apart, top to bottom.
LABEL_SPACING = 13


def spread_labels(lines):
    """The lines with ``label_y`` set: lines ending at the same height get their labels one under the other."""
    ordered = sorted((line for line in lines if line.last_y is not None), key=lambda line: line.last_y)
    placed, previous = {}, None
    for line in ordered:
        y = line.last_y if previous is None else max(line.last_y, previous + LABEL_SPACING)
        placed[line.pillar], previous = round(y, 1), y
    return [replace(line, label_y=placed.get(line.pillar)) for line in lines]


def build_history(scope, scope_id, summaries):
    """The page's model from the scope's summaries, newest first (``GcsResultsStore.list_summaries``)."""
    entries = build_entries(list(summaries))
    return History(scope=scope, scope_id=scope_id, scope_title=scope.capitalize(), entries=entries, chart=build_chart(entries),
                   pillars=tuple(name for name, _ in PILLARS))
