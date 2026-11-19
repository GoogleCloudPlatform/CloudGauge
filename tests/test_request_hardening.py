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
"""Request hardening (v18.6.1): the validator, the key-part guard, the 400s of every route, same-origin on the POST
routes, one scan per scope on ``POST /scan``, the suggestions caps, the request-size limit, and the worker's caller check
with signed tokens."""
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from google.auth import jwt as google_jwt
from google.auth.crypt import rsa as google_rsa

import fakes
from app import create_app, validation
from app.config import MAX_REQUEST_BYTES, MAX_SUGGESTION_TEXT_CHARS, MAX_SUGGESTIONS_PER_REQUEST, Settings
from app.extensions import EXTENSION_KEY
from app.identity import GOOGLE_ISSUERS, KEYS_TTL_SECONDS, CallerVerifier
from app.routes import guards
from app.services import schedules
from app.services.results_store import GcsResultsStore, key_part
from helpers import DEPLOYED_ENV, make_settings, set_env

SA_EMAIL = fakes.TEST_ENV['SERVICE_ACCOUNT_EMAIL']
JOB = '0f8fad5b-d9cb-469f-a165-70867728950e'
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
FORM = {'scope': 'project', 'scope_id': 'web-prod'}
FINDING = {'index': 3, 'finding_text': 'Bucket public-assets is publicly readable', 'project_id': 'data-lake'}


# --- The validator ---

@pytest.mark.parametrize('scope, value', [
    ('organization', '123456789'), ('folder', '42'), ('project', 'web-prod'), ('project', 'a12345'),
    ('project', 'example.com:my-project'), ('project', ' web-prod '), ('organization', ' 123 '),
])
def test_scope_ids_that_are_ones_pass(scope, value):
    assert validation.clean_scope_id(scope, value) == value.strip()


@pytest.mark.parametrize('scope, value, message', [
    ('organization', 'web-prod', "scope_id must be the organization's number."),
    ('folder', '12/34', "scope_id must be the folder's number."),
    ('folder', '', 'scope_id is required.'),
    ('folder', None, 'scope_id is required.'),
    ('folder', 42, 'scope_id must be a string.'),
    ('project', 'p1', 'scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.'),
    ('project', 'Web-Prod', 'scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.'),
    ('project', '../other', 'scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.'),
    ('project', 'web prod', 'scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.'),
    ('project', 'web-prod-', 'scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.'),
    ('project', '1web-prod', 'scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.'),
    ('project', 'x' * 31, 'scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.'),
    ('project', 'web-prod/../x', 'scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.'),
])
def test_scope_ids_that_are_not_ones_are_refused(scope, value, message):
    with pytest.raises(validation.RequestError, match=message.replace('.', r'\.').replace('(', r'\(').replace(')', r'\)')):
        validation.clean_scope_id(scope, value)


def test_scopes_job_ids_shards_counts_and_names():
    assert validation.clean_scope(' project ') == 'project'
    for bad in ('team', '', None, 'Project', ['project']):
        with pytest.raises(validation.RequestError):
            validation.clean_scope(bad)
    assert validation.clean_job_id(JOB) == JOB and validation.clean_job_id(f' {JOB} ') == JOB
    for bad in ('job-1', JOB.upper(), JOB.replace('-', ''), f'{JOB}/x', '', None, 42):
        with pytest.raises(validation.RequestError, match='job_id'):
            validation.clean_job_id(bad)
    assert validation.clean_any_scope_id('123') == '123' and validation.clean_any_scope_id('web-prod') == 'web-prod'
    with pytest.raises(validation.RequestError, match='organization or folder number, or a project ID'):
        validation.clean_any_scope_id('../x')
    assert validation.clean_shard_id('scope') == 'scope' and validation.clean_shard_id('shard-007') == 'shard-007'
    for bad in ('shard-x', 'shards/1', '', 7):
        with pytest.raises(validation.RequestError, match='shard_id'):
            validation.clean_shard_id(bad)
    assert (validation.clean_count(3, 'sweep'), validation.clean_count('12', 'sweep'), validation.clean_count(None, 'sweep', default=1)) == (3, 12, 1)
    for bad in (-1, '1.5', True, None, 'x', 10 ** 7):
        with pytest.raises(validation.RequestError, match='sweep'):
            validation.clean_count(bad, 'sweep')
    assert validation.clean_requested_by(None) is None and validation.clean_requested_by('  ') is None
    assert validation.clean_requested_by(' alice@example.com ') == 'alice@example.com'
    for bad in ('x' * 321, 'line\nbreak', 7):
        with pytest.raises(validation.RequestError):
            validation.clean_requested_by(bad)


def test_the_task_bodies_are_cleaned_as_wholes():
    body = {'scope': 'organization', 'scope_id': '123', 'job_id': JOB, 'requested_by': '', 'extra': 'ignored'}
    assert validation.clean_scan_body(body) == {'scope': 'organization', 'scope_id': '123', 'job_id': JOB}
    assert validation.clean_scan_body({**body, 'requested_by': 'schedule: weekly'})['requested_by'] == 'schedule: weekly'
    assert validation.clean_shard_body({**body, 'shard_id': 'shard-002'})['shard_id'] == 'shard-002'
    assert validation.clean_sweep_body(body)['sweep'] == 1 and validation.clean_sweep_body({**body, 'sweep': '4'})['sweep'] == 4
    for bad in (None, [], 'x', {**body, 'scope': 'team'}, {**body, 'job_id': 'job-1'}):
        with pytest.raises(validation.RequestError):
            validation.clean_scan_body(bad)
    with pytest.raises(validation.RequestError, match='shard_id'):
        validation.clean_shard_body(body)


# --- The key-part guard ---

def test_key_parts_keep_a_key_inside_its_prefix(gcp):
    for ok in (JOB, 'job-1', 'web-prod', 'example.com:my-project', '123', 'scope', 'shard-001', 'a_b.c'):
        assert key_part(ok, 'x') == ok
    assert key_part(7, 'shard_id') == '7'
    for bad in ('a/b', '../x', 'a..b', '', ' a', 'a b', '-lead', None, 7.5, 'x' * 129, 'a\nb'):
        with pytest.raises(ValueError, match='cannot be part of an object key'):
            key_part(bad, 'scope_id')
    store = GcsResultsStore('test-bucket', client=gcp.storage)
    assert store.job_object_name(JOB, 'web-prod', 'status.json') == f'{JOB}/web-prod_status.json'
    assert store.intermediate_prefix(JOB, 'shard-001') == f'intermediate/{JOB}/shards/shard-001/'
    assert store.summaries_prefix('project', 'web-prod') == 'scopes/project/web-prod/'
    assert store.schedule_lock_name('folder', '42') == 'schedules/folder/42.json'
    for call in (lambda: store.read_status('../other', 'web-prod'), lambda: store.read_report(JOB, 'a/b'),
                 lambda: store.open_report(JOB, '..'), lambda: store.read_manifest('x/y'),
                 lambda: store.summaries_prefix('project', 'a/b'), lambda: store.read_schedule_lock('project', '../x'),
                 lambda: store.intermediate_prefix(JOB, 'shards/../x')):
        with pytest.raises(ValueError):
            call()
    assert store.read_all_findings('x/y') == []  # logged, never raised: the findings reader swallows errors
    store.update_status('a/b', 'c', 1, 'x')  # the same for the status writer
    store.write_scan_summary({'scope': 'project', 'scope_id': 'a/b', 'generated_ts': '20261113T120000Z', 'job_id': JOB})
    assert not any('a/b' in name for name in gcp.bucket.objects)


# --- The routes' 400s ---

def test_page_routes_refuse_malformed_identifiers(testing_app):
    http = testing_app.test_client()
    assert http.get(f'/status/{JOB}/project/web-prod').status_code == 200
    for path, message in ((f'/status/job-1/project/web-prod', 'job_id must be a UUID.'),
                          (f'/status/{JOB}/team/web-prod', 'scope must be organization, folder or project.'),
                          (f'/status/{JOB}/project/p1', 'scope_id must be a project ID'),
                          (f'/status/{JOB}/folder/forty-two', "scope_id must be the folder's number."),
                          ('/report/job-1/web-prod', 'job_id must be a UUID.'),
                          (f'/report/{JOB}/Web-Prod', 'scope_id must be an organization or folder number, or a project ID.'),
                          (f'/report/{JOB}/Web-Prod/csv', 'scope_id must be an organization or folder number, or a project ID.'),
                          ('/history/project/p1', 'scope_id must be a project ID'),
                          ('/history/organization/org-1', "scope_id must be the organization's number.")):
        response = http.get(path)
        assert response.status_code == 400 and response.get_data(as_text=True).startswith(message), path
    assert http.get('/history/team/web-prod').status_code == 404  # the scope segment of the history URL was already a 404


def test_api_routes_refuse_malformed_identifiers(testing_app):
    http = testing_app.test_client()
    assert http.get(f'/api/status/{JOB}/web-prod').get_json()['status'] == 'pending'
    assert http.get('/api/status/job-1/web-prod').get_json() == {'error': 'job_id must be a UUID.'}
    assert http.get(f'/api/status/{JOB}/a%20b').status_code == 400
    assert http.post('/api/get-insights', json={'scope': 'project', 'scope_id': 'p1'}).status_code == 400
    assert http.post('/api/get-summary', json={'scope': 'folder', 'scope_id': 'x', 'job_id': JOB}).get_json() == {
        'error': "scope_id must be the folder's number."}
    assert http.post('/api/get-summary', json={'scope': 'team', 'scope_id': '42', 'job_id': JOB}).get_json() == {
        'error': 'scope must be organization, folder or project.'}
    for body in ('null', '[]', '"x"', '{"scope": '):
        response = http.post('/api/get-summary', data=body, content_type='application/json')
        assert (response.status_code, response.get_json()) == (400, {'error': 'The body must be a JSON object.'}), body


# --- Same origin ---

@pytest.mark.parametrize('headers, allowed', [
    ({}, True),
    ({'Sec-Fetch-Site': 'same-origin'}, True),
    ({'Sec-Fetch-Site': 'none'}, True),
    ({'Sec-Fetch-Site': 'same-site'}, False),
    ({'Sec-Fetch-Site': 'cross-site'}, False),
    ({'Sec-Fetch-Site': 'cross-site', 'Origin': 'http://localhost'}, False),  # the browser's label wins
    ({'Origin': 'http://localhost'}, True),
    ({'Origin': 'http://LOCALHOST'}, True),
    ({'Origin': 'https://evil.example'}, False),
    ({'Origin': 'null'}, False),
    ({'Referer': 'http://localhost/report/x/y'}, True),
    ({'Referer': 'https://evil.example/form.html'}, False),
    ({'Origin': 'http://localhost', 'Referer': 'https://evil.example/'}, True),  # Origin is checked first
    ({'Origin': 'https://evil.example', 'Referer': 'http://localhost/'}, False),
])
def test_the_post_routes_are_same_origin_only(headers, allowed, testing_app, gcp):
    http = testing_app.test_client()
    scan = http.post('/scan', data=FORM, headers=headers)
    suggestions = http.post('/api/get-suggestions', json={'findings': []}, headers=headers)
    if allowed:
        assert (scan.status_code, suggestions.status_code, suggestions.get_json()) == (302, 200, {})
        assert len(gcp.tasks.tasks) == 1
    else:
        assert scan.status_code == 403 and scan.get_data(as_text=True).startswith('This request did not come from a CloudGauge page')
        assert suggestions.status_code == 403 and suggestions.get_json() == {
            'error': 'This request did not come from a CloudGauge page (cross-site requests are refused).'}
        assert gcp.tasks.tasks == []
    # GET routes carry no such rule: a link from anywhere opens a page.
    assert http.get('/', headers={'Sec-Fetch-Site': 'cross-site', 'Origin': 'https://evil.example'}).status_code == 200
    assert http.get(f'/api/status/{JOB}/web-prod', headers={'Sec-Fetch-Site': 'cross-site'}).status_code == 200


def test_cross_site_reason_explains_itself():
    assert guards.cross_site_reason({}, 'svc.example') is None
    assert guards.cross_site_reason({'Sec-Fetch-Site': 'cross-site'}, 'svc.example') == 'Sec-Fetch-Site is cross-site'
    assert guards.cross_site_reason({'Origin': 'https://evil.example'}, 'svc.example') == "Origin host 'evil.example' is not 'svc.example'"
    assert guards.cross_site_reason({'Origin': 'https://svc.example:8443'}, 'svc.example:8443') is None
    assert guards.cross_site_reason({'Referer': 'null'}, 'svc.example') == 'Referer is null'


# --- One scan per scope ---

def test_a_scan_is_noted_and_a_second_one_waits(testing_app, gcp, monkeypatch, caplog):
    monkeypatch.setattr(schedules, 'utcnow', lambda: NOW)
    http = testing_app.test_client()
    first = http.post('/scan', data=FORM)
    assert first.status_code == 302
    job_id = first.headers['Location'].split('/')[2]
    note = json.loads(gcp.bucket.objects['schedules/project/web-prod.json'][0])
    assert note == {'job_id': job_id, 'scope': 'project', 'scope_id': 'web-prod', 'requested_by': None, 'started_at': '2026-11-13T12:00:00+00:00'}

    again = http.post('/scan', data=FORM)
    page = again.get_data(as_text=True)
    assert again.status_code == 409 and 'Scan already running' in page and job_id in page
    assert f'href="/status/{job_id}/project/web-prod"' in page and 'Open the running scan' in page and '2026-11-13T12:00:00+00:00' in page
    assert 'Requested by' not in page  # nobody was signed in
    as_json = http.post('/scan', data=FORM, headers={'Accept': 'application/json'})
    assert as_json.status_code == 409 and as_json.get_json() == {
        'error': f'A scan of project web-prod is still running (job {job_id}).', 'job_id': job_id, 'started_at': '2026-11-13T12:00:00+00:00',
        'requested_by': None, 'status_path': f'/status/{job_id}/project/web-prod'}
    assert len(gcp.tasks.tasks) == 1
    # Another scope is free; once the job reports completed (or error) the scope is free too.
    assert http.post('/scan', data={'scope': 'project', 'scope_id': 'data-lake'}).status_code == 302
    gcp.bucket.put(f'{job_id}/web-prod_status.json', json.dumps({'status': 'running', 'progress': 50}), 'application/json')
    assert http.post('/scan', data=FORM).status_code == 409
    gcp.bucket.put(f'{job_id}/web-prod_status.json', json.dumps({'status': 'completed', 'progress': 100}), 'application/json')
    assert http.post('/scan', data=FORM).status_code == 302
    assert len(gcp.tasks.tasks) == 3


def test_a_task_that_never_dispatched_stops_blocking_after_ten_minutes(testing_app, gcp, monkeypatch):
    http = testing_app.test_client()
    clock = NOW
    monkeypatch.setattr(schedules, 'utcnow', lambda: clock)
    assert http.post('/scan', data=FORM).status_code == 302
    clock = NOW + timedelta(minutes=9)
    assert http.post('/scan', data=FORM).status_code == 409
    clock = NOW + timedelta(minutes=11)
    assert http.post('/scan', data=FORM).status_code == 302  # no status file after 10 minutes: the task never came
    assert len(gcp.tasks.tasks) == 2


def test_the_note_is_a_courtesy_the_scan_does_not_depend_on(testing_app, gcp, caplog):
    http = testing_app.test_client()
    gcp.bucket.error = RuntimeError('bucket down')
    with caplog.at_level(logging.WARNING):
        assert http.post('/scan', data=FORM).status_code == 302
    assert any('Could not read the last job noted' in r.message for r in caplog.records)
    assert any('Could not note the job' in r.message for r in caplog.records)
    assert len(gcp.tasks.tasks) == 1


def test_the_signed_in_requester_is_noted(testing_app, gcp, monkeypatch):
    monkeypatch.setattr('app.identity.current_user_email', lambda: 'alice@example.com')
    http = testing_app.test_client()
    assert http.post('/scan', data=FORM).status_code == 302
    assert json.loads(gcp.bucket.objects['schedules/project/web-prod.json'][0])['requested_by'] == 'alice@example.com'
    assert 'Requested by</dt> <dd>alice@example.com' in http.post('/scan', data=FORM).get_data(as_text=True)


# --- The suggestions caps and the request size ---

def test_the_suggestions_batch_is_bounded(testing_app, gcp):
    http = testing_app.test_client()
    gcp.gemini.reply = 'gcloud storage buckets update gs://public-assets --no-public-access-prevention'
    ok = http.post('/api/get-suggestions', json={'findings': [{**FINDING, 'index': i} for i in range(MAX_SUGGESTIONS_PER_REQUEST)]})
    assert ok.status_code == 200 and len(ok.get_json()) == MAX_SUGGESTIONS_PER_REQUEST and 'finding-19' in ok.get_json()
    too_many = http.post('/api/get-suggestions', json={'findings': [FINDING] * (MAX_SUGGESTIONS_PER_REQUEST + 1)})
    assert too_many.get_json() == {'error': f'findings holds {MAX_SUGGESTIONS_PER_REQUEST + 1} items; at most {MAX_SUGGESTIONS_PER_REQUEST} per request.'}
    assert too_many.status_code == 400
    for finding, message in (({**FINDING, 'finding_text': 'x' * (MAX_SUGGESTION_TEXT_CHARS + 1)}, f"A finding's finding_text is longer than {MAX_SUGGESTION_TEXT_CHARS:,} characters."),
                             ({**FINDING, 'finding_text': ''}, "A finding's finding_text must be a non-empty string."),
                             ({**FINDING, 'index': 'three'}, "A finding's index must be a non-negative integer."),
                             ({**FINDING, 'project_id': 'p' * 129}, "A finding's project_id must be a printable name of at most 128 characters."),
                             ('not an object', 'Each finding must be an object with index, finding_text and project_id.')):
        assert http.post('/api/get-suggestions', json={'findings': [finding]}).get_json() == {'error': message}
    assert http.post('/api/get-suggestions', json={'findings': 'x'}).get_json() == {'error': 'findings must be a list.'}
    assert len(gcp.gemini.prompts) == MAX_SUGGESTIONS_PER_REQUEST  # the refused batches never reached Gemini


def test_request_bodies_are_capped(testing_app):
    http = testing_app.test_client()
    too_large = http.post('/api/get-suggestions', data=b'{"findings": [' + b'x' * MAX_REQUEST_BYTES + b']}', content_type='application/json')
    assert too_large.status_code == 413
    assert http.post('/scan', data={'scope': 'project', 'scope_id': 'web-prod', 'pad': 'x' * (MAX_REQUEST_BYTES + 10)}).status_code == 413


# --- The worker's caller ---

class Google:
    """A stand-in for Google's OIDC issuer: signs ID tokens with its current RSA key and publishes the public keys."""

    def __init__(self, kid='kid-a'):
        self.signers, self.keys, self.fetches = {}, {}, 0
        self.rotate(kid)

    def rotate(self, kid):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        public_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.signers[kid] = google_rsa.RSASigner.from_string(private_pem, key_id=kid)
        self.keys = {kid: public_pem}

    def fetch_keys(self):
        self.fetches += 1
        return dict(self.keys)

    def token(self, audience=fakes.WORKER_URL, kid=None, **claims):
        """A signed ID token as Cloud Tasks mints them for the service account; ``claims`` override (``None`` drops one)."""
        now = int(time.time())
        payload = {'iss': 'https://accounts.google.com', 'aud': audience, 'email': SA_EMAIL, 'email_verified': True,
                   'sub': '1029384756', 'azp': '1029384756', 'iat': now - 5, 'exp': now + 3600, **claims}
        payload = {key: value for key, value in payload.items() if value is not None}
        return google_jwt.encode(self.signers[kid or next(iter(self.signers))], payload).decode()


@pytest.fixture
def google():
    return Google()


@pytest.fixture
def worker(gcp, monkeypatch, google):
    """A production-profile worker with the token check at its default (on), trusting ``google``'s keys."""
    set_env(monkeypatch, {name: value for name, value in DEPLOYED_ENV.items() if name != 'WORKER_TOKEN_CHECK'})
    monkeypatch.setenv('CLOUDGAUGE_ROLE', 'worker')
    app = create_app()
    services = app.extensions[EXTENSION_KEY]
    assert services.settings.worker_token_check is True
    services.caller_verifier = CallerVerifier(services.settings, fetch_keys=google.fetch_keys)
    return app.test_client()


def bearer(token):
    return {'Authorization': f'Bearer {token}'}


def test_the_default_is_on_and_the_switch_is_a_switch():
    assert Settings.from_env({**fakes.TEST_ENV}).worker_token_check is True
    assert make_settings(WORKER_TOKEN_CHECK='off').worker_token_check is False
    assert make_settings(WORKER_TOKEN_CHECK='On').worker_token_check is True
    with pytest.raises(ValueError, match='WORKER_TOKEN_CHECK must be on or off'):
        make_settings(WORKER_TOKEN_CHECK='maybe')


def test_without_the_service_accounts_token_the_worker_answers_401(worker, gcp, google, caplog):
    body = {'scope': 'organization', 'scope_id': '123456789', 'name': 'weekly'}
    refused = {'error': 'The worker accepts the service account\'s ID token only.'}
    with caplog.at_level(logging.WARNING):
        assert (worker.post('/scheduled-scan', json=body).status_code, worker.post('/scheduled-scan', json=body).get_json()) == (401, refused)
        assert worker.post('/scheduled-scan', json=body, headers={'Authorization': 'Basic abc'}).status_code == 401
        assert worker.post('/scheduled-scan', json=body, headers={'Authorization': 'Bearer '}).status_code == 401
        assert worker.post('/scheduled-scan', json=body, headers=bearer('not.a.jwt')).status_code == 401
        other = Google('kid-z')
        assert worker.post('/scheduled-scan', json=body, headers=bearer(other.token())).status_code == 401  # another key
        assert worker.post('/scheduled-scan', json=body, headers=bearer(google.token(iss='https://evil.example'))).status_code == 401
        assert worker.post('/scheduled-scan', json=body, headers=bearer(google.token(audience='https://other.example'))).status_code == 401
        assert worker.post('/scheduled-scan', json=body, headers=bearer(google.token(email='mallory@example.com'))).status_code == 401
        assert worker.post('/scheduled-scan', json=body, headers=bearer(google.token(email=None))).status_code == 401
        assert worker.post('/scheduled-scan', json=body, headers=bearer(google.token(email_verified=False))).status_code == 401
        expired = google.token(iat=int(time.time()) - 7200, exp=int(time.time()) - 3600)
        assert worker.post('/scheduled-scan', json=body, headers=bearer(expired)).status_code == 401
    assert gcp.tasks.tasks == []
    reasons = [r.message for r in caplog.records if 'refused' in r.message or 'rejected' in r.message]
    assert any('no bearer token' in r for r in reasons) and any('is not the service account' in r for r in reasons)
    assert any("is not Google's" in r for r in reasons) and any('wrong audience' in r for r in reasons)
    for every in ('/run-scan', '/scan-shard', '/run-aggregation', '/sweep'):
        assert worker.post(every, json={}).status_code == 401, every  # the token comes before the body


def test_with_the_service_accounts_token_the_worker_works(worker, gcp, google):
    body = {'scope': 'organization', 'scope_id': '123456789', 'name': 'weekly'}
    # The audiences Cloud Tasks and Cloud Scheduler use: the worker's own URL bare and with the path (the task URL), the
    # request's own URL with and without the path.
    for audience in (fakes.WORKER_URL, f'{fakes.WORKER_URL}/', f'{fakes.WORKER_URL}/scheduled-scan', 'http://localhost/scheduled-scan',
                     'http://localhost', 'http://localhost/'):
        response = worker.post('/scheduled-scan', json={**body, 'scope_id': str(100 + len(audience))}, headers=bearer(google.token(audience=audience)))
        assert response.status_code == 202, audience
    # Behind Cloud Run the container speaks plain HTTP; the scheme the front saw comes in X-Forwarded-Proto.
    forwarded = {**bearer(google.token(audience='https://localhost/scheduled-scan')), 'X-Forwarded-Proto': 'https'}
    assert worker.post('/scheduled-scan', json={**body, 'scope_id': '777'}, headers=forwarded).status_code == 202
    assert worker.post('/scheduled-scan', json={**body, 'scope_id': '778'}, headers=bearer(google.token(audience='https://localhost/scheduled-scan'))).status_code == 401
    assert len(gcp.tasks.tasks) == 7
    # The token first, then the body: a malformed task with a good token is a 400, not a 401.
    assert worker.post('/run-scan', json={'scope': 'team'}, headers=bearer(google.token())).get_json() == {'error': 'scope must be organization, folder or project.'}
    assert worker.post('/scan-shard', json={**body, 'job_id': JOB}, headers=bearer(google.token())).get_json() == {'error': 'shard_id is required.'}
    assert worker.post('/sweep', json={**body, 'job_id': JOB, 'sweep': -1}, headers=bearer(google.token())).status_code == 400
    assert worker.post('/run-aggregation', json=['x'], headers=bearer(google.token())).status_code == 400
    # Google rotates its keys: an unknown key ID is fetched once more.
    google.rotate('kid-b')
    assert worker.post('/scheduled-scan', json={**body, 'scope_id': '555'}, headers=bearer(google.token(kid='kid-b'))).status_code == 202
    assert google.fetches == 2


def test_worker_audience_is_accepted_when_set(gcp, monkeypatch, google):
    set_env(monkeypatch, {name: value for name, value in DEPLOYED_ENV.items() if name != 'WORKER_TOKEN_CHECK'})
    monkeypatch.setenv('CLOUDGAUGE_ROLE', 'worker')
    monkeypatch.setenv('WORKER_AUDIENCE', 'https://cloudgauge-worker-123.us-central1.run.app')
    app = create_app()
    app.extensions[EXTENSION_KEY].caller_verifier = CallerVerifier(app.extensions[EXTENSION_KEY].settings, fetch_keys=google.fetch_keys)
    http = app.test_client()
    body = {'scope': 'folder', 'scope_id': '42', 'name': 'nightly'}
    assert http.post('/scheduled-scan', json=body, headers=bearer(google.token(audience='https://cloudgauge-worker-123.us-central1.run.app'))).status_code == 202
    assert http.post('/scheduled-scan', json=body, headers=bearer(google.token(audience='https://canary---cloudgauge-worker-123.us-central1.run.app'))).status_code == 401


def test_the_check_is_off_when_told_and_outside_production(gcp, monkeypatch):
    for env in ({**DEPLOYED_ENV, 'WORKER_TOKEN_CHECK': 'off'}, {**DEPLOYED_ENV, 'CLOUDGAUGE_ENV': 'testing', 'WORKER_TOKEN_CHECK': 'on'}):
        set_env(monkeypatch, {**env, 'CLOUDGAUGE_ROLE': 'worker'})
        http = create_app().test_client()
        response = http.post('/scheduled-scan', json={'scope': 'folder', 'scope_id': 'x'})
        assert response.status_code == 400, env  # no token asked for: straight to the body


def test_the_verifier_caches_keys_and_names_its_rejections(google, caplog):
    clock = [1_000_000.0]
    verifier = CallerVerifier(make_settings(), fetch_keys=google.fetch_keys, now=lambda: clock[0])
    audiences = (fakes.WORKER_URL,)
    assert verifier.verify(google.token(), audiences)['email'] == SA_EMAIL
    assert verifier.verify(google.token(), audiences)['iss'] in GOOGLE_ISSUERS and google.fetches == 1
    clock[0] += KEYS_TTL_SECONDS + 1
    assert verifier.verify(google.token(), audiences) and google.fetches == 2
    with caplog.at_level(logging.WARNING):
        assert verifier.verify(google.token(aud=None), audiences) is None
        assert CallerVerifier(make_settings(SERVICE_ACCOUNT_EMAIL=None), fetch_keys=google.fetch_keys).verify(google.token(), audiences) is None
    assert any('SERVICE_ACCOUNT_EMAIL is not set' in r.message for r in caplog.records)
