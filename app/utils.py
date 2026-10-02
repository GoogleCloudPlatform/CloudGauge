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
"""Shared helpers for services and checks.

- ``configure_logging``: the legacy ``logging.basicConfig`` call, safe to repeat
- ``call_api_with_backoff``: exponential backoff on HTTP 429 (legacy ``_call_api_with_backoff``)
- ``find_col_index``: CSV header lookup
- ``ThrottledProgressReporter``: the legacy ``run_scan_worker`` progress closure

Moved from ``cloudgauge.py`` (Phase 1). Nothing here does I/O at import time.
"""
import logging
import random
import threading
import time

from google.api_core import exceptions as core_exceptions

from app.config import LOG_DATEFMT, LOG_FORMAT, STATUS_UPDATE_INTERVAL_SECONDS


def configure_logging(level=logging.INFO):
    """Configures root logging with the legacy format.

    Safe to call more than once: like ``logging.basicConfig``, it does nothing if
    the root logger already has handlers.
    """
    # Configures logging to display INFO level messages with a timestamp.
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATEFMT
    )


# --- Helper function for backoff ---

def call_api_with_backoff(api_call_func, context_message="API call", on_error=None):
    """
    Wraps a Google Cloud API list call with exponential backoff to handle 429 rate limit errors.

    Args:
        api_call_func: A lambda or function that executes the actual API call
                       (e.g., lambda: client.list_recommendations(parent=parent)).
        context_message: Names the call in the log lines.
        on_error: Called with the exception when the call fails for good (any
                  error other than a 429, or a 429 after the last retry), right
                  before the empty result is returned. The checks use it to
                  record the project as not checked (``app.checks.not_checked``).

    Returns:
        The results of the API call, or an empty list if all retries fail.
    """
    max_retries = 5
    initial_delay = 1.5  # seconds
    backoff_factor = 2

    for attempt in range(max_retries):
        try:
            # Execute the provided API call function
            return api_call_func()
        except core_exceptions.ResourceExhausted as e:
            # This is the specific exception for 429 errors from google-api-core
            if attempt < max_retries - 1:
                # Calculate wait time with exponential backoff and random jitter
                delay = (initial_delay * (backoff_factor ** attempt)) + random.uniform(0, 1)
                logging.warning(
                    f"Rate limit hit (429) for for {context_message}. Retrying in {delay:.2f} seconds... (Attempt {attempt + 1}/{max_retries})"
                )
                time.sleep(delay)
            else:
                logging.error(f"API rate limit exceeded for {context_message} after {max_retries} attempts. Error: {e}")
                if on_error:
                    on_error(e)
                return [] # Return empty list after final failure
        except Exception as e:
            # For any other error, don't retry, just log it and move on.
            logging.error(f"An unexpected API error occurred for {context_message}: {e}")
            if on_error:
                on_error(e)
            return []
    return [] # Should not be reached, but as a fallback


def find_col_index(header_map, possible_names):
    """
    Helper function to find the index of a column from a list of possible names.
    This provides flexibility when parsing CSV files with slightly different headers.

    Args:
        header_map (dict): A dictionary mapping lowercase header names to their indices.
        possible_names (list): A list of possible header names to search for.

    Returns:
        int: The index of the first matching column found.

    Raises:
        KeyError: If none of the possible column names are found in the header map.
    """
    for name in possible_names:
        if name in header_map:
            return header_map[name]
    raise KeyError(f"Could not find any of the required columns: {possible_names}")


class ThrottledProgressReporter:
    """
    Thread-safe progress callback that throttles status writes.

    Replaces the ``progress_reporter`` closure of the legacy ``run_scan_worker``.
    The latest progress is always recorded, but ``update_fn(progress, current_task)``
    is only called if more than ``interval`` seconds have passed since the last
    write. Call :meth:`flush` after the run so the final state is always written.

    Args:
        update_fn (callable): Writes one status update.
        interval (float): Minimum number of seconds between two writes.
        clock (callable): Returns the current time in seconds (replaceable in tests).
    """

    def __init__(self, update_fn, interval=STATUS_UPDATE_INTERVAL_SECONDS, clock=time.time):
        self._update_fn = update_fn
        self._interval = interval
        self._clock = clock
        self._last_update_time = 0
        # A lock ensures thread-safe updates to the last_update_time variable.
        self._lock = threading.Lock()
        self.final_progress = {"progress": 0, "task": ""}

    def __call__(self, progress, current_task):
        current_time = self._clock()

        # Store the latest progress regardless of timing
        self.final_progress["progress"] = progress
        self.final_progress["task"] = current_task

        with self._lock:
            if (current_time - self._last_update_time) > self._interval:
                self._update_fn(progress, current_task)
                self._last_update_time = current_time

    def flush(self):
        """Writes the latest progress unconditionally; call it once the checks are done."""
        # --- Final, unconditional update after checks complete ---
        # This ensures the user sees the 100% completion of the checks phase, even if
        # it happened within the 2-second throttle window.
        if self.final_progress["task"]:
            self._update_fn(self.final_progress["progress"], self.final_progress["task"])
