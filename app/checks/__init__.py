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
"""Scan checks, their registry, and the concurrent runner.

- ``security``, ``reliability``, ``operations``, ``cost``, ``network``: the checks
- ``categories``: check result name -> report category
- ``registry``: ``CheckSpec`` and ``build_check_plan()`` (what runs, with which args)
- ``runner``: ``run_all_checks()`` executes the plan on a ``ThreadPoolExecutor``

Every check keeps its legacy positional signature and adds a keyword-only
``sink`` (a ``GcsResultsStore``) for writing findings. No eager submodule
imports here.
"""
