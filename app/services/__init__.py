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
"""GCP-facing services.

- ``gcp``               late-bound auth/discovery pass-throughs, lazy shared clients
- ``results_store``     ``GcsResultsStore``: findings, org-policy data, status, reports
- ``tasks``             Cloud Tasks queue check and scan-task enqueueing
- ``worker_url``        ``WORKER_URL`` override or Cloud Run self-discovery
- ``resource_manager``  project, location, and organization discovery
- ``org_policies``      best-practices CSV and effective org policies
- ``insights``          on-demand cost-optimization insights
- ``gemini``            Vertex AI remediation commands and executive summaries

Services receive what they need as arguments (``settings``, clients) and never use
Flask's ``current_app`` or ``request``. No eager submodule imports here.
"""
