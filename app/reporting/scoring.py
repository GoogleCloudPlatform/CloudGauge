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
"""The score of a category: what counts, what does not, and how it is worded (v15.2).

A category's score is the share of its checks that reached a verdict and were
compliant: ``compliant / (compliant + action required + investigation
recommended)``. A check in **Error** — including the *Projects not checked*
item — is coverage, not a verdict: it is stated next to the score (the
``evidence`` line, "1 could not be checked"), never inside it, so a transient
API failure does not move a score. **Informational** checks (the briefings)
stay outside, as they always were. **Organization Policies** is one check
worth ``compliant policies / total policies`` of a pass, so 128 policies
cannot outweigh 12 checks. A category with **no verdict at all** is *not
assessed*: no number, no band.

Bands: above 90 *high* (Healthy), above 70 *medium* (Needs attention),
otherwise *low* (At risk); ``NOT_ASSESSED`` when there is nothing to band.

``app.reporting.context`` applies the rule to a scan's findings and
``app.reporting.changes`` applies the same functions to a stored scan summary
(``scores_from_checks``, ``overview_from_checks``), so a previous scan is
always read under the current rule and a change of rule never shows as a
change of posture.
"""
from dataclasses import dataclass

# The statuses that are a verdict against the category; Compliant is the verdict for it.
VERDICT_FAILING = ("Action Required", "Investigation Recommended")
# The score class of a category without a verdict (the templates' fourth band).
NOT_ASSESSED = "none"
NOT_ASSESSED_TEXT = "Not assessed"


def score_class_for(score):
    """``high`` / ``medium`` / ``low`` for a score, ``NOT_ASSESSED`` for ``None``."""
    if score is None:
        return NOT_ASSESSED
    return "high" if score > 90 else "medium" if score > 70 else "low"


def plural(count, noun):
    return f"{count:,} {noun}{'' if count == 1 else 's'}"


@dataclass(frozen=True)
class Tally:
    """What a category's checks came to: the counts behind its score, and the score.

    ``policies_total`` is set only for the category that evaluated Organization
    Policies (Security & Identity, on organization scans); ``None`` means the
    policies were not part of the scan, 0 that none were defined.
    """
    compliant: int = 0  # checks with the verdict Compliant
    failing: int = 0  # checks with a verdict against: Action Required or Investigation Recommended
    not_checked: int = 0  # checks in Error, which could not look (coverage, outside the score)
    policies_compliant: int | None = None  # Organization Policies set as recommended...
    policies_total: int | None = None  # ...of the policies evaluated

    @property
    def has_policies(self):
        return bool(self.policies_total)

    @property
    def verdicts(self):
        """The checks the score is over: Organization Policies counts as one."""
        return self.compliant + self.failing + (1 if self.has_policies else 0)

    @property
    def assessed(self):
        return self.verdicts > 0

    @property
    def score(self):
        """0–100, or ``None`` when no check reached a verdict."""
        if not self.assessed:
            return None
        credit = self.compliant + (self.policies_compliant / self.policies_total if self.has_policies else 0)
        return credit / self.verdicts * 100

    @property
    def score_display(self):
        """``"55"``; empty when not assessed (the templates then say so in words)."""
        score = self.score
        return "" if score is None else f"{score:.0f}"

    @property
    def score_class(self):
        return score_class_for(self.score)

    @property
    def evidence(self):
        """The facts behind the score, in the words every page uses:

        ``"7 of 12 checks compliant · 18 of 128 policies as recommended · 1 could not be checked"``,
        or ``"no check reached a verdict · 2 could not be checked"`` when not assessed.
        """
        parts = []
        checks = self.compliant + self.failing
        if checks:
            parts.append(f"{self.compliant:,} of {plural(checks, 'check')} compliant")
        if self.has_policies:
            noun = "policy" if self.policies_total == 1 else "policies"
            parts.append(f"{self.policies_compliant:,} of {self.policies_total:,} {noun} as recommended")
        if not parts:
            parts.append("no check reached a verdict")
        if self.not_checked:
            parts.append(f"{self.not_checked:,} could not be checked")
        return " · ".join(parts)


def tally_statuses(statuses, policies=None):
    """The ``Tally`` of a category from its checks' statuses (one per check, Organization Policies left out)
    and, when the policies were evaluated, ``(compliant, total)``."""
    tally = Tally(
        compliant=sum(1 for status in statuses if status == "Compliant"),
        failing=sum(1 for status in statuses if status in VERDICT_FAILING),
        not_checked=sum(1 for status in statuses if status == "Error"),
    )
    if policies is not None:
        compliant, total = policies
        tally = Tally(tally.compliant, tally.failing, tally.not_checked, compliant, total)
    return tally


# --- The rule applied to a stored scan summary (app.reporting.changes.summarize) ----------------------------------

# The summary's name for the Organization Policies entry (app.reporting.changes.ORG_POLICIES_CHECK).
ORG_POLICIES = "Organization Policies"


def summary_policies(entry):
    """``(compliant, total)`` of a summary's Organization Policies entry: version 2 stores them; version 1 stored
    the total as ``rows`` and every differing policy as an identity, which gives the same numbers."""
    policies = entry.get("policies")
    if policies is not None:
        return policies["compliant"], policies["total"]
    total = entry.get("rows", 0)
    return total - len(entry.get("identities", [])), total


def tallies_from_checks(checks):
    """Category name → ``Tally`` from a summary's ``checks`` (name → ``{"category", "status", ...}``)."""
    statuses, policies = {}, {}
    for name, entry in checks.items():
        category = entry.get("category")
        if category is None:
            continue
        if name == ORG_POLICIES:
            policies[category] = summary_policies(entry)
        else:
            statuses.setdefault(category, []).append(entry.get("status"))
    return {category: tally_statuses(statuses.get(category, []), policies.get(category))
            for category in list(statuses) + [c for c in policies if c not in statuses]}


def scores_from_checks(checks):
    """Category name → score (``None`` when not assessed) from a summary's ``checks``, under the current rule."""
    return {category: tally.score for category, tally in tallies_from_checks(checks).items()}


def overview_from_checks(checks):
    """The Overview counts from a summary's ``checks``, under the current rule: one check, one count, Organization
    Policies once by its own status (``app.reporting.context.build_report_context`` counts the live scan the same way)."""
    counts = {"action_count": 0, "investigation_count": 0, "compliant_count": 0, "error_count": 0}
    keys = {"Action Required": "action_count", "Investigation Recommended": "investigation_count",
            "Compliant": "compliant_count", "Error": "error_count"}
    for entry in checks.values():
        key = keys.get(entry.get("status"))
        if key:
            counts[key] += 1
    return counts
