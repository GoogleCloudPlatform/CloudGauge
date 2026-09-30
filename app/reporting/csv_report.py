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
shared ``evaluate_org_policies`` instead of a second copy of that logic.
"""
import csv
import io

from app.reporting.context import evaluate_org_policies


def generate_csv_data(all_results):
    """
    Generates a comprehensive CSV report from the categorized results.

    Args:
        all_results (dict): The dictionary of categorized findings from `run_all_checks`.

    Returns:
        str: A string containing the full report in CSV format.
    """
    output = io.StringIO()
    writer = csv.writer(output)

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
        
        for finding_group in results:
            check_name = finding_group.get('Check', 'Unnamed Check')
            status = finding_group.get('Status', 'N/A')
            details = finding_group.get('Finding')

            if isinstance(details, list) and details and isinstance(details[0], dict):
                # For structured data, create headers and write each dict as a new row
                headers = ['Check', 'Status'] + list(details[0].keys())
                writer.writerow(headers)
                for detail_dict in details:
                    row_data = [check_name, status] + list(detail_dict.values())
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
