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
"""GEMINI_MODEL=auto: model discovery, caching, and fallback (new; the legacy code hardcoded a model)."""
import pytest
from google.genai import errors as genai_errors

import fakes
from app.config import AUTO_GEMINI_MODEL, FALLBACK_GEMINI_MODEL, Settings, _gemini_model
from app.services import gemini as gemini_service
from app.services.gemini import FALLBACK_CACHE_TTL_SECONDS, MODEL_CACHE_TTL_SECONDS, newest_stable_flash_model

AUTO = Settings(project_id='test-project', gemini_model=AUTO_GEMINI_MODEL)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


# --- newest_stable_flash_model ---

def test_picks_the_highest_version_numerically():
    assert newest_stable_flash_model(['gemini-3.8-flash', 'gemini-3.10-flash', 'gemini-3.9-flash']) == 'gemini-3.10-flash'
    assert newest_stable_flash_model(['gemini-10-flash', 'gemini-9.9-flash']) == 'gemini-10-flash'


def test_skips_previews_lite_and_specialized_models():
    assert newest_stable_flash_model(fakes.FakeGemini.MODELS) == fakes.FakeGemini.NEWEST_STABLE_FLASH
    assert newest_stable_flash_model([
        'gemini-4-flash-preview', 'gemini-4-flash-lite', 'gemini-4-flash-image', 'gemini-4-flash-cyber',
        'gemini-live-4-flash', 'gemini-4-pro', 'gemini-flash-latest', 'gemini-3.5-flash']) == 'gemini-3.5-flash'


def test_accepts_resource_names_and_bare_ids():
    assert newest_stable_flash_model(['publishers/google/models/gemini-3.7-flash', 'gemini-3.5-flash']) == 'gemini-3.7-flash'


@pytest.mark.parametrize('names', [[], ['gemini-3-flash-preview', 'gemini-3.5-flash-lite', 'text-embedding-005']])
def test_none_when_nothing_matches(names):
    assert newest_stable_flash_model(names) is None


# --- GEMINI_MODEL parsing ---

@pytest.mark.parametrize('value, expected', [
    (None, 'auto'), ('', 'auto'), ('  ', 'auto'), ('auto', 'auto'), (' AUTO ', 'auto'),
    ('gemini-3.5-flash', 'gemini-3.5-flash'), (' gemini-3.5-flash ', 'gemini-3.5-flash'),
])
def test_gemini_model_setting(value, expected):
    assert _gemini_model(value) == expected
    env = {} if value is None else {'GEMINI_MODEL': value}
    assert Settings.from_env(env).gemini_model == expected


# --- resolve_model ---

def test_pinned_model_needs_no_lookup(gcp):
    assert gemini_service.resolve_model(Settings(gemini_model='gemini-3.5-flash')) == 'gemini-3.5-flash'
    assert gcp.gemini.list_calls == 0


def test_auto_is_cached_until_the_ttl_expires(gcp):
    clock = Clock()
    assert gemini_service.resolve_model(AUTO, clock=clock) == 'gemini-3.8-flash'
    assert gcp.gemini.clients == [('test-project', 'global')]
    gcp.gemini.models.append('publishers/google/models/gemini-3.9-flash')  # a new release
    clock.now += MODEL_CACHE_TTL_SECONDS - 1
    assert gemini_service.resolve_model(AUTO, clock=clock) == 'gemini-3.8-flash'
    assert gcp.gemini.list_calls == 1
    clock.now += 1
    assert gemini_service.resolve_model(AUTO, clock=clock) == 'gemini-3.9-flash'
    assert gcp.gemini.list_calls == 2


def test_auto_caches_per_project_and_location(gcp):
    gemini_service.resolve_model(AUTO)
    gemini_service.resolve_model(Settings(project_id='other', gemini_model=AUTO_GEMINI_MODEL))
    gemini_service.resolve_model(Settings(project_id='test-project', vertex_location='us-central1', gemini_model=AUTO_GEMINI_MODEL))
    gemini_service.resolve_model(AUTO)
    assert gcp.gemini.list_calls == 3


@pytest.mark.parametrize('broken', ['list_error', 'no_match'])
def test_auto_falls_back_when_the_lookup_fails(broken, gcp, caplog):
    clock = Clock()
    if broken == 'list_error':
        gcp.gemini.list_error = PermissionError('403 aiplatform.models.list denied')
    else:
        gcp.gemini.models = ['publishers/google/models/gemini-3-flash-preview']
    assert gemini_service.resolve_model(AUTO, clock=clock) == FALLBACK_GEMINI_MODEL
    assert 'using gemini-flash-latest' in caplog.text
    # The fallback is retried sooner than a successful lookup.
    gcp.gemini.list_error = None
    gcp.gemini.models = fakes.FakeGemini().models
    clock.now += FALLBACK_CACHE_TTL_SECONDS - 1
    assert gemini_service.resolve_model(AUTO, clock=clock) == FALLBACK_GEMINI_MODEL
    clock.now += 1
    assert gemini_service.resolve_model(AUTO, clock=clock) == 'gemini-3.8-flash'
    assert gcp.gemini.list_calls == 2


# --- Calling the model ---

def test_auto_falls_back_once_when_the_model_is_not_served(gcp):
    gcp.gemini.reply = 'gcloud storage buckets update gs://b --uniform-bucket-level-access'
    gcp.gemini.unavailable = {'gemini-3.8-flash'}
    assert gemini_service.generate_remediation_command('finding', 'p1', settings=AUTO).startswith('gcloud')
    assert [model for model, _ in gcp.gemini.prompts] == ['gemini-3.8-flash', FALLBACK_GEMINI_MODEL]
    # Later calls go straight to the fallback.
    assert gemini_service.generate_executive_summary('csv', settings=AUTO) == gcp.gemini.reply
    assert [model for model, _ in gcp.gemini.prompts][2:] == [FALLBACK_GEMINI_MODEL]
    assert gcp.gemini.list_calls == 1


def test_pinned_model_does_not_fall_back(gcp):
    gcp.gemini.unavailable = {'gemini-0-flash'}
    with pytest.raises(genai_errors.ClientError):
        gemini_service.generate_executive_summary('csv', settings=Settings(gemini_model='gemini-0-flash'))
    assert [model for model, _ in gcp.gemini.prompts] == ['gemini-0-flash']


def test_unavailable_fallback_is_reported(gcp):
    gcp.gemini.list_error = RuntimeError('offline')
    gcp.gemini.unavailable = {FALLBACK_GEMINI_MODEL}
    assert gemini_service.generate_remediation_command('finding', 'p1', settings=AUTO) == 'Error generating remediation command.'
    assert [model for model, _ in gcp.gemini.prompts] == [FALLBACK_GEMINI_MODEL]


@pytest.mark.parametrize('error, rate_limited', [
    (genai_errors.ClientError(429, {'error': {'code': 429, 'status': 'RESOURCE_EXHAUSTED', 'message': 'quota'}}), True),
    (genai_errors.ClientError(400, {'error': {'code': 400, 'status': 'INVALID_ARGUMENT', 'message': 'bad'}}), False),
    (genai_errors.ServerError(503, {'error': {'code': 503, 'status': 'UNAVAILABLE', 'message': 'busy'}}), False),
    (RuntimeError('429'), False),
])
def test_only_http_429_is_retried(error, rate_limited, gcp, monkeypatch):
    monkeypatch.setattr(gemini_service.time, 'sleep', lambda seconds: None)
    gcp.gemini.genai_error = error
    result = gemini_service.generate_remediation_command('finding', 'p1', settings=AUTO)
    if rate_limited:
        assert (result, len(gcp.gemini.prompts)) == ('Error: API rate limit exceeded.', 3)
    else:
        assert (result, len(gcp.gemini.prompts)) == ('Error generating remediation command.', 1)


def test_get_client_targets_vertex_ai(monkeypatch):
    created = []
    monkeypatch.setattr(gemini_service.genai, 'Client', lambda **kwargs: created.append(kwargs) or object())
    gemini_service.get_client.cache_clear()
    try:
        assert gemini_service.get_client('p', 'global') is gemini_service.get_client('p', 'global')
        assert created == [{'vertexai': True, 'project': 'p', 'location': 'global'}]
    finally:
        gemini_service.get_client.cache_clear()
