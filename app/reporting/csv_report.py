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
"""The CSV report (legacy ``generate_csv_data``).

Moved unchanged, except that the Organization Policies rows now come from the
shared ``evaluate_org_policies`` instead of a second copy of that logic, and
that a report compared with a previous scan adds a trailing ``New since last
scan`` column (``yes`` or empty) to every structured row, so an action plan
can be filtered on it in a spreadsheet. The existing columns do not move.
"""
import csv
import io

from app.reporting.context import evaluate_org_policies

NEW_COLUMN = "New since last scan"


def generate_csv_data(all_results, row_matchers=None):
    """
    Generates a comprehensive CSV report from the categorized results.

    Args:
        all_results (dict): The dictionary of categorized findings from `run_all_checks`.
        row_matchers (dict, optional): Check name → ``app.reporting.changes.RowMatcher``
            (``ReportContext.row_matchers``). When given, structured rows end with
            the ``New since last scan`` column; the rows of a check without a
            matcher get an empty value.

    Returns:
        str: A string containing the full report in CSV format.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    compared = row_matchers is not None

    # --- Write Org Policies Section  ---
    writer.writerow(['Organization Policies'])
    writer.writerow(['Category', 'Policy', 'Expected Value', 'Current Value', 'Status'])
    org_policy_data = all_results.get('Organization Policies')
    if org_policy_data:
        best_practices, current_policies = org_policy_data
        for category, results in evaluate_org_policies(best_practices, current_policies):
            for result in results:
                writer.writerow([category, result.display_name, result.expected_value, result.current_value, result.status])

    # --- Helper to Write Other Sections ---
    def write_section(title, results):
        if not isinstance(results, list) or not results:
            return
        writer.writerow([]) # Spacer row
        writer.writerow([title])
        trackers = {}  # a check's rows may span several records; one tracker numbers them in order

        for finding_group in results:
            check_name = finding_group.get('Check', 'Unnamed Check')
            status = finding_group.get('Status', 'N/A')
            details = finding_group.get('Finding')

            if isinstance(details, list) and details and isinstance(details[0], dict):
                # For structured data, create headers and write each dict as a new row
                headers = ['Check', 'Status'] + list(details[0].keys()) + ([NEW_COLUMN] if compared else [])
                writer.writerow(headers)
                matcher = row_matchers.get(check_name) if compared else None
                if matcher is not None and check_name not in trackers:
                    trackers[check_name] = matcher.tracker()
                tracker = trackers.get(check_name)
                for detail_dict in details:
                    row_data = [check_name, status] + list(detail_dict.values())
                    if compared:
                        row_data.append('yes' if tracker is not None and tracker.is_new(detail_dict) else '')
                    writer.writerow(row_data)
                writer.writerow([]) # Add a space after a detailed check
            else:
                # Fallback for simple findings (e.g., compliant checks)
                writer.writerow(['Check', 'Status', 'Details'])
                details_str = '; '.join(map(str, details)) if isinstance(details, list) else str(details)
                writer.writerow([check_name, status, details_str])

    # --- Main Loop to Write All Other Sections ---
    for category_name, findings in all_results.items():
        if category_name != 'Organization Policies':
            write_section(category_name, findings)
            
    return output.getvalue()
