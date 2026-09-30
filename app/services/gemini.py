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
"""Gemini (Vertex AI) helpers: remediation commands and executive summaries.

Moved from ``cloudgauge.py`` (Phase 1). The prompts are unchanged. Calls go
through the Google Gen AI SDK (``google-genai``) on Vertex AI, which replaces the
deprecated ``vertexai.generative_models``. The project and location come from
``app.config.Settings`` (``PROJECT_ID``, ``VERTEX_LOCATION``).

Model selection (``GEMINI_MODEL``):

- ``auto`` (default): the newest stable Gemini Flash model that Vertex AI lists
  for the project, e.g. ``gemini-3.8-flash``. Stable means a plain
  ``gemini-<version>-flash`` ID: previews, Lite, and specialized variants
  (image, TTS, live, ...) are skipped. The choice is cached for
  ``MODEL_CACHE_TTL_SECONDS``, so new releases are picked up without a deploy.
  If the list can't be read, or the chosen model is not served, the
  ``FALLBACK_GEMINI_MODEL`` alias is used instead.
- anything else: used as the model ID, e.g. ``gemini-3.5-flash`` to pin a model.
"""
import functools
import logging
import random
import re
import threading
import time

from google import genai
from google.genai import errors as genai_errors

from app.config import AUTO_GEMINI_MODEL, FALLBACK_GEMINI_MODEL, get_settings

MODEL_CACHE_TTL_SECONDS = 6 * 60 * 60
FALLBACK_CACHE_TTL_SECONDS = 10 * 60  # retry the lookup sooner after a failure
_STABLE_FLASH_MODEL = re.compile(r"^gemini-(\d+(?:\.\d+)*)-flash$")

_model_cache = {}  # (project, location) -> (model, expires at, per the clock passed to resolve_model)
_model_cache_lock = threading.Lock()


@functools.lru_cache(maxsize=None)
def get_client(project, location):
    """Returns the shared Gen AI client for Vertex AI in ``project`` and ``location``."""
    return genai.Client(vertexai=True, project=project, location=location)


def reset_model_cache():
    """Forgets the models chosen for ``auto`` (tests; a new lookup happens on next use)."""
    with _model_cache_lock:
        _model_cache.clear()


def newest_stable_flash_model(model_names):
    """
    Returns the ID of the highest-versioned stable Flash model among ``model_names``, or None.

    Args:
        model_names (iterable of str): Model IDs or resource names ("publishers/google/models/<id>").
    """
    best = None
    for name in model_names:
        model_id = name.rsplit('/', 1)[-1]
        match = _STABLE_FLASH_MODEL.match(model_id)
        if match:
            version = tuple(int(part) for part in match.group(1).split('.'))
            if best is None or version > best[0]:
                best = (version, model_id)
    return best[1] if best else None


def _remember(key, model, ttl, clock):
    _model_cache[key] = (model, clock() + ttl)


def resolve_model(settings, *, clock=time.monotonic):
    """
    Returns the model ID to call: ``settings.gemini_model``, or for ``auto`` the
    newest stable Flash model (see the module docstring).
    """
    if settings.gemini_model != AUTO_GEMINI_MODEL:
        return settings.gemini_model

    key = (settings.project_id, settings.vertex_location)
    # The lock also makes concurrent first requests share one lookup.
    with _model_cache_lock:
        cached = _model_cache.get(key)
        if cached and cached[1] > clock():
            return cached[0]
        try:
            models = get_client(*key).models.list(config={'query_base': True})
            model = newest_stable_flash_model(m.name for m in models if m.name)
        except Exception as e:
            logging.warning(f"Could not list Gemini models for GEMINI_MODEL=auto: {e}")
            model = None
        if model:
            _remember(key, model, MODEL_CACHE_TTL_SECONDS, clock)
            logging.info(f"GEMINI_MODEL=auto: using {model}.")
        else:
            model = FALLBACK_GEMINI_MODEL
            _remember(key, model, FALLBACK_CACHE_TTL_SECONDS, clock)
            logging.warning(f"GEMINI_MODEL=auto: no stable Flash model found; using {model}.")
        return model


def _generate_content(prompt, settings, *, clock=time.monotonic):
    """Sends ``prompt`` to the resolved model; with ``auto``, falls back once if that model isn't served."""
    client = get_client(settings.project_id, settings.vertex_location)
    model = resolve_model(settings, clock=clock)
    try:
        return client.models.generate_content(model=model, contents=prompt)
    except genai_errors.ClientError as e:
        if e.code != 404 or settings.gemini_model != AUTO_GEMINI_MODEL or model == FALLBACK_GEMINI_MODEL:
            raise
        logging.warning(f"Gemini model {model} is not available ({e}); falling back to {FALLBACK_GEMINI_MODEL}.")
        with _model_cache_lock:
            _remember((settings.project_id, settings.vertex_location), FALLBACK_GEMINI_MODEL, FALLBACK_CACHE_TTL_SECONDS, clock)
        return client.models.generate_content(model=FALLBACK_GEMINI_MODEL, contents=prompt)


def _is_rate_limit(error):
    """True for HTTP 429 (quota or rate limit) from the Gen AI SDK."""
    return isinstance(error, genai_errors.APIError) and error.code == 429


# --- Vertex AI Remediation Generation ---

def generate_remediation_command(finding_text: str, project_id: str, *, settings=None) -> str:
    """
    Uses the Gemini model to generate a gcloud CLI command to remediate a given finding.
    Includes exponential backoff for handling API rate limits.

    Args:
        finding_text (str): The detailed text of the compliance finding.
        project_id (str): The project ID to be used in the generated command.
        settings (Settings, optional): Overrides the model, project, and location read from the environment.

    Returns:
        str: A single-line gcloud command or an error message.
    """
    settings = settings or get_settings()

    # Configuration for the retry logic
    max_retries = 3
    initial_delay = 2  # seconds
    backoff_factor = 2

    for attempt in range(max_retries):
        try:
            prompt = f"""
            You are a Google Cloud security expert. Your task is to generate a precise and executable gcloud command to fix the following compliance finding.
            - The command must be a single line.
            - Do not add any explanation, introductory text, or markdown formatting.
            - Use the provided project ID '{project_id}' in the command.
            **Compliance Finding:**
            "{finding_text}"
            **gcloud command:**
            """
            
            response = _generate_content(prompt, settings)
            command = response.text.strip()

            if command.startswith("gcloud"):
                return command  # Success, exit the loop
            else:
                return "AI could not generate a valid command." # Model returned a non-command, exit

        except Exception as e:
            if not _is_rate_limit(e):
                # For any other error (not a 429), fail immediately without retrying
                print(f"⚠️ An unexpected error occurred calling Gemini API: {e}")
                return "Error generating remediation command."
            # This specifically catches the 429 rate limit error
            if attempt < max_retries - 1:
                # Calculate wait time with exponential backoff and random jitter
                delay = (initial_delay * (backoff_factor ** attempt)) + random.uniform(0, 1)
                print(f"⚠️ Rate limit hit for a finding. Retrying in {delay:.2f} seconds... (Attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
            else:
                print(f"❌ Gemini API rate limit exceeded after {max_retries} attempts. Error: {e}")
                return "Error: API rate limit exceeded." # Final failure after all retries
    
    return "Error: All retry attempts failed." # Should not be reached, but as a fallback


def generate_executive_summary(csv_data, *, settings=None):
    """
    Uses the Gemini model to write an executive summary of a scan's CSV report.
    Moved from the ``/api/get-summary`` route, which keeps the GCS lookup and HTTP handling.

    Args:
        csv_data (str): The full CSV report.
        settings (Settings, optional): Overrides the model, project, and location read from the environment.

    Returns:
        str: The summary, in GitHub-flavored Markdown.
    """
    settings = settings or get_settings()

    # 3. Use the optimized prompt
    prompt = f"""
        You are a strategic Google Cloud advisor specializing in security posture enhancement and cost optimization. Your task is to provide a balanced and action-oriented executive summary based on the following compliance and best practices report, which is provided in CSV format.

        **Report Data:**
        ```csv
        {csv_data}
        ```

        **Instructions:**
        1.  Start with a single, concise introductory sentence that summarizes the overall state of the organization's cloud environment.
        2.  Identify the top 3-5 primary opportunities for enhancement and optimization. Use a bulleted list.
        3.  For each area, briefly explain the implication and the opportunity in plain, business-focused language. Frame the points constructively.
            * Instead of: "High security risk due to publicly accessible storage buckets."
            * Use language like: "Opportunity to Enhance Data Security: By adjusting permissions on several storage buckets, we can significantly strengthen our data security posture."
            * Instead of: "Significant cost savings are being missed by not addressing idle VMs."
            * Use language like: "Opportunity for Cost Optimization: A number of virtual machines have been identified as idle, representing a clear opportunity to reduce operational costs."
        4.  Conclude with a brief, forward-looking statement about the recommended next steps to capitalize on these opportunities.
        5.  Keep the entire summary professional, concise, and easy for a non-technical executive to understand. Do not repeat the raw data from the report.
        6.  **Tone and Voice:** Adopt a constructive and partnership-oriented tone. The goal is to highlight opportunities for improvement and strategic gains, not to create alarm. Focus on what can be achieved.
        7.  Format your entire response in GitHub-flavored Markdown.
        """
    
    # 4. Generate the summary
    response = _generate_content(prompt, settings)
    return response.text
