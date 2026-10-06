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
"""Who is signed in behind Identity-Aware Proxy (v16): ``app.identity``.

The verifier accepts only an assertion IAP signed for this very service (ES256
with a published key, IAP's issuer, the ``/projects/NUMBER/locations/REGION/
services/NAME`` audience, not expired) and takes the email from it; the plain
``X-Goog-Authenticated-User-Email`` header is never read. The pages then show
*Signed in as*, ``/scan`` records the person as ``requested_by``, and the
report and its summary say *Requested by*. Without IAP nothing changes: no
name, no ``requested_by``, the legacy task body.
"""
import json
import logging
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.auth import jwt as google_jwt
from google.auth.crypt import es256

import fakes
import samples
import test_fanout as sharded
from app import identity, scan_job
from app.extensions import EXTENSION_KEY
from app.identity import IAP_ASSERTION_HEADER, IAP_ISSUER, KEYS_TTL_SECONDS, IapVerifier
from app.services.tasks import build_scan_task
from helpers import make_settings

PROJECT_NUMBER = '123456789012'
AUDIENCE = f'/projects/{PROJECT_NUMBER}/locations/us-central1/services/{fakes.K_SERVICE}'
EMAIL = 'alice@example.com'
RAW_EMAIL_HEADER = 'X-Goog-Authenticated-User-Email'
REJECTED = 'IAP assertion rejected'


def keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()).decode()
    public_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return private_pem, public_pem


class Iap:
    """A stand-in for IAP: signs assertions with its current key and publishes the public keys."""

    def __init__(self, kid='kid-1'):
        self.signers = {}
        self.keys = {}  # what https://www.gstatic.com/iap/verify/public_key would answer
        self.fetches = 0
        self.rotate(kid)

    def rotate(self, kid):
        private_pem, public_pem = keypair()
        self.signers[kid] = es256.ES256Signer.from_string(private_pem, key_id=kid)
        self.keys = {kid: public_pem}

    def fetch_keys(self):
        self.fetches += 1
        return dict(self.keys)

    def assertion(self, kid=None, **claims):
        """A signed assertion with IAP's claims; ``claims`` override them (``None`` drops one)."""
        now = int(time.time())  # google-auth checks iat/exp against the real clock
        payload = {'iss': IAP_ISSUER, 'aud': AUDIENCE, 'email': EMAIL, 'sub': 'accounts.google.com:10769150350006150715113082367',
                   'identity_source': 'GOOGLE', 'iat': now - 5, 'exp': now + 600, **claims}
        payload = {key: value for key, value in payload.items() if value is not None}
        return google_jwt.encode(self.signers[kid or next(iter(self.signers))], payload).decode()


def make_verifier(iap, clock=None, **settings_overrides):
    settings = make_settings('testing', PROJECT_NUMBER=PROJECT_NUMBER, **settings_overrides)
    return IapVerifier(settings, fetch_keys=iap.fetch_keys, fetch_project_number=lambda: PROJECT_NUMBER, now=clock)


def with_assertion(assertion):
    return {IAP_ASSERTION_HEADER: assertion, RAW_EMAIL_HEADER: f'accounts.google.com:{EMAIL}'}


def rejections(caplog):
    return [record.message for record in caplog.records if record.message.startswith(REJECTED)]


# --- The verifier ---

def test_a_valid_assertion_names_the_person():
    iap = Iap()
    verifier = make_verifier(iap)
    assert verifier.audience() == AUDIENCE
    assert verifier.email_from(with_assertion(iap.assertion())) == EMAIL
    claims = verifier.verify(iap.assertion())
    assert claims['email'] == EMAIL and claims['sub'].startswith('accounts.google.com:') and claims['aud'] == AUDIENCE


def test_without_an_assertion_nobody_is_signed_in():
    """The plain email header is never read: a service reachable without IAP could be told any name."""
    verifier = make_verifier(Iap())
    assert verifier.email_from({}) is None
    assert verifier.email_from({RAW_EMAIL_HEADER: f'accounts.google.com:{EMAIL}'}) is None
    assert verifier.email_from({IAP_ASSERTION_HEADER: ''}) is None


@pytest.mark.parametrize('reason, overrides', [
    ('another service', {'aud': f'/projects/{PROJECT_NUMBER}/locations/us-central1/services/other'}),
    ('another project', {'aud': f'/projects/999/locations/us-central1/services/{fakes.K_SERVICE}'}),
    ('an audience in URL form', {'aud': f'https://{fakes.K_SERVICE}-{PROJECT_NUMBER}.us-central1.run.app'}),
    ('another issuer', {'iss': 'https://accounts.google.com'}),
    ('no issuer', {'iss': None}),
    ('expired', {'exp': int(time.time()) - 60}),
    ('no expiry', {'exp': None}),
    ('no email', {'email': None}),
    ('an empty email', {'email': ''}),
])
def test_an_assertion_that_is_not_for_this_service_or_not_current_is_rejected(reason, overrides, caplog):
    iap = Iap()
    assert make_verifier(iap).email_from(with_assertion(iap.assertion(**overrides))) is None, reason
    assert len(rejections(caplog)) == 1


@pytest.mark.parametrize('garbage', ['not-a-jwt', 'a.b', 'a.b.c', 'eyJhbGciOiJub25lIn0.e30.'])
def test_garbage_is_rejected_not_raised(garbage, caplog):
    assert make_verifier(Iap()).email_from({IAP_ASSERTION_HEADER: garbage}) is None
    assert len(rejections(caplog)) == 1


def test_a_key_iap_does_not_publish_is_rejected_after_one_refetch(caplog):
    """An attacker's own key, under IAP's key ID or a new one, fails the signature check."""
    iap, rogue = Iap(), Iap()
    verifier = make_verifier(iap)
    assert verifier.email_from(with_assertion(iap.assertion())) == EMAIL and iap.fetches == 1
    assert verifier.email_from(with_assertion(rogue.assertion())) is None  # same kid-1, another private key
    assert iap.fetches == 1  # the kid is known: no refetch, the signature simply fails
    rogue.rotate('kid-9')
    assert verifier.email_from(with_assertion(rogue.assertion('kid-9'))) is None
    assert iap.fetches == 2  # an unknown kid is fetched once more, in case IAP rotated; it had not
    assert len(rejections(caplog)) == 2


def test_a_key_rotation_is_followed_with_one_refetch():
    iap = Iap()
    verifier = make_verifier(iap)
    assert verifier.email_from(with_assertion(iap.assertion())) == EMAIL and iap.fetches == 1
    iap.rotate('kid-2')
    assert verifier.email_from(with_assertion(iap.assertion('kid-2'))) == EMAIL and iap.fetches == 2
    assert verifier.email_from(with_assertion(iap.assertion('kid-2'))) == EMAIL and iap.fetches == 2


def test_the_keys_are_cached_for_an_hour():
    clock = [1_700_000_000.0]
    iap = Iap()
    verifier = make_verifier(iap, clock=lambda: clock[0])
    for _ in range(3):
        assert verifier.email_from(with_assertion(iap.assertion())) == EMAIL
    assert iap.fetches == 1
    clock[0] += KEYS_TTL_SECONDS + 1
    assert verifier.email_from(with_assertion(iap.assertion())) == EMAIL and iap.fetches == 2


def test_a_key_fetch_failure_rejects_the_assertion_and_is_retried_next_time(caplog):
    iap = Iap()
    verifier = make_verifier(iap)
    calls = []

    def flaky_fetch():
        calls.append(1)
        if len(calls) == 1:
            raise OSError('gstatic unreachable')
        return iap.fetch_keys()

    verifier._fetch_keys = flaky_fetch
    assert verifier.email_from(with_assertion(iap.assertion())) is None
    assert 'gstatic unreachable' in rejections(caplog)[0]
    assert verifier.email_from(with_assertion(iap.assertion())) == EMAIL


def test_the_project_number_comes_from_the_metadata_server_when_not_configured():
    iap = Iap()
    lookups = []

    def fetch_project_number():
        lookups.append(1)
        return f'{PROJECT_NUMBER}\n'

    verifier = IapVerifier(make_settings('testing'), fetch_keys=iap.fetch_keys, fetch_project_number=fetch_project_number)
    for _ in range(2):
        assert verifier.email_from(with_assertion(iap.assertion())) == EMAIL
    assert lookups == [1]  # read once


def test_without_a_project_number_nothing_is_verified_and_the_log_says_so_once(caplog):
    iap = Iap()

    def no_metadata_server():
        raise OSError('metadata.google.internal: no route to host')

    verifier = IapVerifier(make_settings('testing'), fetch_keys=iap.fetch_keys, fetch_project_number=no_metadata_server)
    for _ in range(2):
        assert verifier.email_from(with_assertion(iap.assertion())) is None
    warnings = [record.message for record in caplog.records if record.levelname == 'WARNING']
    assert len(warnings) == 1 and 'set PROJECT_NUMBER' in warnings[0] and 'no route to host' in warnings[0]
    assert iap.fetches == 0  # nothing to check an assertion against, so the keys are never fetched


def test_the_audience_needs_the_location_and_the_service_name(caplog):
    verifier = make_verifier(Iap(), K_SERVICE=None)
    assert verifier.audience() is None
    assert 'K_SERVICE' in caplog.text
    assert identity.expected_audience('42', 'europe-west1', 'cg') == '/projects/42/locations/europe-west1/services/cg'


# --- In the app ---

def install(app, iap):
    """Gives ``app`` a verifier that trusts ``iap``'s keys; returns it."""
    verifier = make_verifier(iap)
    app.extensions[EXTENSION_KEY].identity_verifier = verifier
    return verifier


def test_current_user_email_is_computed_once_per_request(testing_app):
    iap = Iap()
    verifier = install(testing_app, iap)
    verified = []
    original = verifier.verify
    verifier.verify = lambda assertion: verified.append(1) or original(assertion)

    assert identity.current_user_email() is None  # outside a request
    with testing_app.test_request_context(headers=with_assertion(iap.assertion())):
        assert identity.current_user_email() == EMAIL
        assert identity.current_user_email() == EMAIL
    assert verified == [1]
    with testing_app.test_request_context():
        assert identity.current_user_email() is None


def test_the_pages_say_who_is_signed_in(testing_app, gcp):
    iap = Iap()
    install(testing_app, iap)
    http = testing_app.test_client()

    home = http.get('/', headers=with_assertion(iap.assertion())).get_data(as_text=True)
    assert '<span class="signed-in">Signed in as alice@example.com</span>' in home
    status = http.get('/status/job-1/project/p1', headers=with_assertion(iap.assertion())).get_data(as_text=True)
    assert 'const signed_in_as = "alice@example.com";' in status

    # Not behind IAP (or the raw header alone): the pages say nothing.
    for headers in ({}, {RAW_EMAIL_HEADER: f'accounts.google.com:{EMAIL}'}):
        assert 'Signed in as' not in http.get('/', headers=headers).get_data(as_text=True)
        assert 'const signed_in_as = "";' in http.get('/status/job-1/project/p1', headers=headers).get_data(as_text=True)


def test_the_name_is_escaped_on_the_pages(testing_app, gcp):
    iap = Iap()
    install(testing_app, iap)
    headers = with_assertion(iap.assertion(email='"<b>x</b>"@example.com'))
    home = testing_app.test_client().get('/', headers=headers).get_data(as_text=True)
    assert '<b>x</b>' not in home and 'Signed in as &#34;&lt;b&gt;x&lt;/b&gt;&#34;@example.com' in home


def test_a_scan_records_who_asked_for_it(testing_app, gcp):
    iap = Iap()
    install(testing_app, iap)
    http = testing_app.test_client()
    form = {'scope': 'project', 'scope_id': 'p1'}

    assert http.post('/scan', data=form, headers=with_assertion(iap.assertion())).status_code == 302
    assert http.post('/scan', data=form).status_code == 302
    assert http.post('/scan', data=form, headers={RAW_EMAIL_HEADER: f'accounts.google.com:{EMAIL}'}).status_code == 302
    bodies = [json.loads(task['http_request']['body']) for _, task in gcp.tasks.tasks]
    assert bodies[0] == {'scope': 'project', 'scope_id': 'p1', 'job_id': bodies[0]['job_id'], 'requested_by': EMAIL}
    for body in bodies[1:]:  # the legacy body, exactly
        assert body == {'scope': 'project', 'scope_id': 'p1', 'job_id': body['job_id']}


def test_build_scan_task_adds_requested_by_only_when_known():
    task = build_scan_task('https://w.example', 'sa@p.iam.gserviceaccount.com', 'project', 'p1', 'job-1', requested_by=EMAIL)
    assert json.loads(task['http_request']['body']) == {'scope': 'project', 'scope_id': 'p1', 'job_id': 'job-1', 'requested_by': EMAIL}
    for unknown in (None, ''):
        task = build_scan_task('https://w.example', 'sa@p.iam.gserviceaccount.com', 'project', 'p1', 'job-1', requested_by=unknown)
        assert json.loads(task['http_request']['body']) == {'scope': 'project', 'scope_id': 'p1', 'job_id': 'job-1'}


# --- In the report ---

JOB_ID, SCOPE_ID = 'job-7', 'p-alpha'
REQUESTED_BY_ROW = f'<dt>Requested by</dt><dd>{EMAIL}</dd>'


@pytest.fixture
def scripted_scan(monkeypatch):
    """An inline scan that writes the sample findings and the org policies, like a real one."""
    def run_all_checks(scope, scope_id, job_id, progress_callback=None, *, sink, projects=None):
        sink.write_org_policies(job_id, samples.BEST_PRACTICES, samples.CURRENT_POLICIES)
        for finding in samples.all_findings():
            sink.write_finding(job_id, finding['Check'].replace(' ', '_'), finding)
        return True

    monkeypatch.setattr(scan_job, 'run_all_checks', run_all_checks)


def summary_of(bucket):
    (name,) = [name for name in bucket.objects if name.startswith('scopes/')]
    return json.loads(bucket.objects[name][0])


def test_the_report_says_who_requested_the_scan(client, gcp, scripted_scan):
    payload = {'scope': 'project', 'scope_id': SCOPE_ID, 'job_id': JOB_ID, 'requested_by': EMAIL}
    assert client.post('/run-scan', json=payload).status_code == 200
    html = gcp.bucket.objects[f'{JOB_ID}/{SCOPE_ID}_report.html'][0]
    assert REQUESTED_BY_ROW in html
    assert html.index('<dt>Report ID</dt>') < html.index(REQUESTED_BY_ROW)  # right after the report ID
    assert summary_of(gcp.bucket)['requested_by'] == EMAIL


def test_a_scan_nobody_signed_in_for_has_no_requested_by(client, gcp, scripted_scan):
    """The legacy task body; the row is absent, the summary says unknown."""
    assert client.post('/run-scan', json={'scope': 'project', 'scope_id': SCOPE_ID, 'job_id': JOB_ID}).status_code == 200
    html = gcp.bucket.objects[f'{JOB_ID}/{SCOPE_ID}_report.html'][0]
    assert 'Requested by' not in html
    assert summary_of(gcp.bucket)['requested_by'] is None


def test_a_sharded_scan_carries_requested_by_through_the_manifest_to_the_report(monkeypatch):
    store, queue = sharded.memory_results_store(), sharded.Queue()
    sharded.fake_plans(monkeypatch, [])
    fan = sharded.make_fanout(store, queue)
    manifest = fan.dispatch('organization', sharded.SCOPE_ID, sharded.JOB, sharded.projects(3), requested_by=EMAIL)
    assert manifest['requested_by'] == EMAIL
    assert store.read_manifest(sharded.JOB)['requested_by'] == EMAIL
    for shard_id in manifest['shards']:
        assert fan.run_shard({**sharded.BODY, 'shard_id': shard_id}) is True
    assert fan.aggregate(sharded.BODY) is True
    assert REQUESTED_BY_ROW in store.read_report(sharded.JOB, sharded.SCOPE_ID, 'html')
    bucket = store.client.bucket(store.bucket_name)
    (summary_name,) = bucket.object_names('scopes/')
    assert json.loads(bucket.blob(summary_name).download_as_text())['requested_by'] == EMAIL


def test_a_sharded_scan_without_a_person_has_no_requested_by(monkeypatch):
    store, queue = sharded.memory_results_store(), sharded.Queue()
    sharded.fake_plans(monkeypatch, [])
    fan = sharded.make_fanout(store, queue)
    manifest = fan.dispatch('organization', sharded.SCOPE_ID, sharded.JOB, sharded.projects(3))
    assert 'requested_by' not in manifest  # the manifest of a v15 job in flight during an upgrade reads the same
    for shard_id in manifest['shards']:
        fan.run_shard({**sharded.BODY, 'shard_id': shard_id})
    assert fan.aggregate(sharded.BODY) is True
    assert 'Requested by' not in store.read_report(sharded.JOB, sharded.SCOPE_ID, 'html')


def test_the_logging_of_rejections_never_includes_the_assertion(caplog):
    caplog.set_level(logging.WARNING)
    iap = Iap()
    assertion = iap.assertion(aud='/projects/1/locations/x/services/y')
    assert make_verifier(iap).email_from({IAP_ASSERTION_HEADER: assertion}) is None
    assert assertion not in caplog.text and assertion.split('.')[2] not in caplog.text
