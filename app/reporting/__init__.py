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
"""Report generation.

- ``context``      view-model: groups findings, evaluates org policies, scores sections
- ``scoring``      the score rule (v15.2): verdicts only, Organization Policies one check, *Not assessed*
- ``html_report``  renders the self-contained HTML report (``templates/report/``)
- ``csv_report``   the CSV report

Nothing here uses Flask: reports render without an app or request context.
No eager submodule imports here.
"""
