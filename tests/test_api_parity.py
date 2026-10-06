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
"""HTTP parity: each request gets the same response from the new app as from the legacy module.

Every test sends the same request to ``legacy_client`` (the frozen pre-refactor
module) and to ``client`` (``create_app()`` in the production profile, as
gunicorn runs it). Both talk to the same GCP fakes, so the calls they make can
be compared too. Error pages are compared line by line; the index and status
pages, redesigned in v14.2, on what they tell the browser (``page_facts``);
everything else byte for byte. ``/run-scan`` is covered by test_worker.py.
"""
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest
from google.api_core.exceptions import PermissionDenied, ResourceExhausted
from google.genai import errors as genai_errors

import fakes
from app import create_app
from app.services import insights as insights_service
from helpers import assert_same_response, normalized_lines, page_facts

SA_EMAIL = fakes.TEST_ENV['SERVICE_ACCOUNT_EMAIL']
XSS = '"><img src=x onerror=alert(1)>'  # no "/": a URL segment can't contain one


def send_both(legacy_client, client, method, path, **kwargs):
    """Sends the same request to both apps: legacy first, then new."""
    return legacy_client.open(path, method=method, **kwargs), client.open(path, method=method, **kwargs)


def assert_parity(legacy_client, client, method, path, *, html=False, facts=None, **kwargs):
    """Asserts both apps respond the same way and returns the new app's response."""
    legacy_response, response = send_both(legacy_client, client, method, path, **kwargs)
    assert_same_response(legacy_response, response, html=html, facts=facts)
    return response


def halves(calls):
    """Splits calls recorded during a parity test into (legacy's, new app's)."""
    assert len(calls) % 2 == 0, calls
    middle = len(calls) // 2
    return calls[:middle], calls[middle:]


# --- Pages ---

def test_index_page(legacy_client, client):
    response = assert_parity(legacy_client, client, 'GET', '/', facts=page_facts)
    assert response.status_code == 200
    assert page_facts(response.get_data(as_text=True)) == {
        'forms': [('/scan', 'post')],
        'fields': [('scope', False, False), ('scope_id', True, True)],  # the resource select waits for a scope
        'options': ['', 'organization', 'folder', 'project', ''],
        'submit_disabled': True,
        'constants': [],
        'urls': ['/api/list-resources?scope=${selectedScope}'],
    }


def test_scan_enqueues_the_legacy_task(legacy_client, client, gcp, monkeypatch):
    job_id = uuid.UUID('0f8fad5b-d9cb-469f-a165-70867728950e')
    monkeypatch.setattr(uuid, 'uuid4', lambda: job_id)
    response = assert_parity(legacy_client, client, 'POST', '/scan', data={'scope': 'folder', 'scope_id': '42'})
    assert response.status_code == 302
    assert response.headers['Location'] == f'/status/{job_id}/folder/42'

    (legacy_parent, legacy_task), (parent, task) = gcp.tasks.tasks
    # New: the task has a dispatch deadline (the legacy task had none, so Cloud Tasks
    # retried a scan still running after 10 minutes). Everything else is the legacy task.
    assert task.pop('dispatch_deadline') == timedelta(minutes=30)
    assert (parent, task) == (legacy_parent, legacy_task)
    assert parent == 'projects/test-project/locations/us-central1/queues/test-queue'
    request = task['http_request']
    assert request['url'] == f'{fakes.WORKER_URL}/run-scan'
    assert request['headers'] == {'Content-Type': 'application/json'}
    assert request['oidc_token'] == {'service_account_email': SA_EMAIL}
    assert json.loads(request['body']) == {'scope': 'folder', 'scope_id': '42', 'job_id': str(job_id)}


@pytest.mark.parametrize('kwargs', [
    {'data': {'scope': 'project', 'scope_id': ''}},
    {'data': {'scope': '', 'scope_id': 'p1'}},
    {'data': {'scope': 'project'}},  # no scope_id field: 400 from request.form
    {'data': {}},
    {'json': {'scope': 'project', 'scope_id': 'p1'}},  # JSON instead of a form
])
def test_scan_rejects_incomplete_forms(kwargs, legacy_client, client, gcp):
    response = assert_parity(legacy_client, client, 'POST', '/scan', html=True, **kwargs)
    assert response.status_code == 400
    assert gcp.tasks.tasks == []


def test_status_page(legacy_client, client, gcp):
    startup_auth_calls = len(gcp.auth_scopes)  # the new app's startup looked up its URL
    response = assert_parity(legacy_client, client, 'GET', '/status/job-1/organization/123456789', facts=page_facts)
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    signed_url = 'https://storage.example/test-bucket/job-1/123456789_report.csv?X-Goog-Signature=abc&X-Goog-Expires=3600'
    assert page_facts(page) == {
        'forms': [], 'fields': [], 'options': [], 'submit_disabled': False,
        'constants': [('job_id', '"job-1"'), ('scope_id', '"123456789"'), ('signed_csv_url', f'"{signed_url}"')],
        'urls': ['/api/status/${job_id}/${scope_id}', '/report/${job_id}/${scope_id}'],
    }
    assert 'const scope = "organization";' in normalized_lines(page)  # new in v14.2: the card names the scope

    (legacy_blob, legacy_kwargs), (blob, kwargs) = gcp.bucket.signed_url_requests
    assert blob == legacy_blob == 'job-1/123456789_report.csv'
    expirations = legacy_kwargs.pop('expiration'), kwargs.pop('expiration')
    assert kwargs == legacy_kwargs == {'version': 'v4', 'method': 'GET', 'service_account_email': SA_EMAIL,
                                       'access_token': fakes.FakeCredentials.token}
    for expiration in expirations:  # one hour from now
        assert abs(expiration - datetime.now(timezone.utc) - timedelta(hours=1)) < timedelta(minutes=1)
    assert gcp.auth_scopes[startup_auth_calls:] == [['https://www.googleapis.com/auth/cloud-platform']] * 2


def test_status_page_without_a_signed_url(legacy_client, client, gcp):
    gcp.bucket.signing_error = RuntimeError('Permission iam.serviceAccounts.signBlob denied')
    response = assert_parity(legacy_client, client, 'GET', '/status/job-1/project/my-project', facts=page_facts)
    assert response.status_code == 200
    assert 'const signed_csv_url = "#";' in normalized_lines(response.get_data(as_text=True))


def test_status_page_escapes_url_values(legacy_client, client):
    path = f'/status/{quote(XSS, safe="")}/project/{quote(XSS, safe="")}'
    response = assert_parity(legacy_client, client, 'GET', path, facts=page_facts)
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert XSS not in page
    assert 'const job_id = "&#34;&gt;&lt;img src=x onerror=alert(1)&gt;";' in normalized_lines(page)
    assert 'const scope_id = "&#34;&gt;&lt;img src=x onerror=alert(1)&gt;";' in normalized_lines(page)


def test_report_is_served_as_stored(legacy_client, client, gcp):
    stored = '<!DOCTYPE html>\n<html><body>CloudGauge Report: Project p1 &amp; more</body></html>\n'
    gcp.bucket.put('job-1/p1_report.html', stored, 'text/html')
    response = assert_parity(legacy_client, client, 'GET', '/report/job-1/p1')
    assert response.status_code == 200
    assert response.get_data(as_text=True) == stored


def test_missing_report(legacy_client, client):
    response = assert_parity(legacy_client, client, 'GET', '/report/job-1/p1')
    assert (response.status_code, response.get_data(as_text=True)) == (404, 'Report not found or is still generating.')


def test_report_storage_error(legacy_client, client, gcp):
    gcp.bucket.error = RuntimeError('503 Service Unavailable')
    response = assert_parity(legacy_client, client, 'GET', '/report/job-1/p1')
    assert (response.status_code, response.get_data(as_text=True)) == (500, 'Could not retrieve report.')


# --- /api/status ---

def test_status_is_pending_before_the_worker_starts(legacy_client, client):
    response = assert_parity(legacy_client, client, 'GET', '/api/status/job-1/p1')
    assert response.get_json() == {'status': 'pending', 'progress': 0, 'current_task': 'Waiting for task to start...'}


def test_status_is_read_from_the_bucket(legacy_client, client, gcp):
    status = {'job_id': 'job-1', 'scope_id': 'p1', 'progress': 35, 'current_task': '(5/14) Finished: GKE Hygiene',
              'status': 'running', 'timestamp': '2026-09-29T10:00:00+00:00'}
    gcp.bucket.put('job-1/p1_status.json', json.dumps(status), 'application/json')
    response = assert_parity(legacy_client, client, 'GET', '/api/status/job-1/p1')
    assert response.get_json() == status


def test_status_storage_error(legacy_client, client, gcp):
    gcp.bucket.error = RuntimeError('503 Service Unavailable')
    response = assert_parity(legacy_client, client, 'GET', '/api/status/job-1/p1')
    assert response.status_code == 500
    assert response.get_json() == {'status': 'error', 'message': '503 Service Unavailable'}


# --- /api/list-resources ---

@pytest.fixture
def org_resources(gcp):
    gcp.assets.add('folders', '111', 'Engineering')
    gcp.assets.add('folders', '222', 'Analytics')
    gcp.assets.add('folders', '333', 'Platform', parent='folders/111')
    gcp.assets.add('folders', '444', 'Platform', parent='folders/222')  # the same name under another parent
    gcp.assets.add('folders', '555', 'Shared', parent='folders/999')  # a parent the search did not return
    gcp.assets.add('projects', 'web-prod', 'Web Prod')
    gcp.assets.add('projects', 'data-lake', 'Data Lake')
    return gcp.assets


def test_list_resources_organization(legacy_client, client, org_resources):
    response = assert_parity(legacy_client, client, 'GET', '/api/list-resources?scope=organization')
    assert response.status_code == 200
    assert response.get_json() == [{'id': fakes.ORG_ID, 'name': f'Organization {fakes.ORG_ID}'}]
    assert org_resources.requests == []  # nothing to search for


@pytest.mark.parametrize('scope, expected', [
    ('folder', [{'id': '222', 'name': 'Analytics (222)'}, {'id': '444', 'name': 'Analytics / Platform (444)'},
                {'id': '111', 'name': 'Engineering (111)'}, {'id': '333', 'name': 'Engineering / Platform (333)'},
                {'id': '555', 'name': 'Shared (555)'}]),
    ('project', [{'id': 'data-lake', 'name': 'Data Lake (data-lake)'}, {'id': 'web-prod', 'name': 'Web Prod (web-prod)'}]),
])
def test_list_resources_offers_active_resources_named_by_path_and_id(scope, expected, client, org_resources):
    """v15.6: the picker's one search asks for ACTIVE resources (a folder pending deletion was still offered) and
    names a folder by its path from the organization down and its ID, since folder names are unique only among
    siblings; a parent outside the account's view starts the path lower. Legacy searched without a state filter
    and named folders by display name alone, so this route is no longer compared with it (the organization
    case and the error cases still are)."""
    response = client.get(f'/api/list-resources?scope={scope}')
    assert response.status_code == 200
    assert response.get_json() == expected
    asset_type = fakes.ASSET_TYPES['folders' if scope == 'folder' else 'projects']
    assert org_resources.requests == [{'scope': f'organizations/{fakes.ORG_ID}', 'asset_types': [asset_type], 'query': 'state:ACTIVE'}]


def test_folder_labels_walk_the_path_and_survive_a_cycle():
    from app.services.resource_manager import folder_labels

    assert folder_labels({'1': ('Top', None), '2': ('Mid', '1'), '3': ('Leaf', '2')}) == \
           {'1': 'Top (1)', '2': 'Top / Mid (2)', '3': 'Top / Mid / Leaf (3)'}
    assert folder_labels({'1': ('A', '2'), '2': ('B', '1')}) == {'1': 'B / A (1)', '2': 'A / B (2)'}  # never loops


def test_list_resources_requires_a_scope(legacy_client, client, gcp):
    startup_calls = list(gcp.discovery.calls)
    response = assert_parity(legacy_client, client, 'GET', '/api/list-resources')
    assert response.status_code == 400
    assert response.get_json() == {'error': 'Scope parameter is required'}
    assert gcp.discovery.calls == startup_calls  # rejected before the ancestry lookup


def test_list_resources_rejects_an_unknown_scope(legacy_client, client):
    response = assert_parity(legacy_client, client, 'GET', '/api/list-resources?scope=billing-account')
    assert response.status_code == 400
    assert response.get_json() == {'error': 'Invalid scope'}


def test_list_resources_asset_api_error(legacy_client, client, gcp):
    gcp.assets.error = PermissionDenied('cloudasset.assets.searchAllResources')
    response = assert_parity(legacy_client, client, 'GET', '/api/list-resources?scope=folder')
    assert response.status_code == 500
    assert response.get_json() == {'error': f'Failed to list resources: {gcp.assets.error}'}


@pytest.mark.parametrize('break_ancestry', ['no organization', 'error'])
def test_list_resources_without_a_parent_organization(break_ancestry, legacy_client, client, gcp):
    if break_ancestry == 'error':
        gcp.discovery.ancestry_error = RuntimeError('resourcemanager.projects.get denied')
    else:
        gcp.discovery.ancestry = {'ancestor': [{'resourceId': {'type': 'project', 'id': 'test-project'}}]}
    response = assert_parity(legacy_client, client, 'GET', '/api/list-resources?scope=project')
    assert response.status_code == 500
    assert response.get_json() == {'error': 'Could not determine parent organization'}


# --- /api/get-insights ---

INSIGHT_PROJECTS = [{'projectId': 'web-prod', 'displayName': 'Web Prod'}, {'projectId': 'data-lake', 'displayName': 'Data Lake'}]
INSIGHT_LOCATIONS = (['us-central1-a', 'europe-west1-b'], ['us-central1', 'global'])


@pytest.fixture
def insight_scope(legacy, monkeypatch):
    """Both implementations see the same projects and locations. Returns the project list; clear it for "no projects"."""
    projects = list(INSIGHT_PROJECTS)
    for module in (legacy, insights_service):
        monkeypatch.setattr(module, 'list_projects_for_scope', lambda scope, scope_id: projects)
        monkeypatch.setattr(module, 'get_active_compute_locations', lambda all_projects, on_error=None: INSIGHT_LOCATIONS)
    return projects


@pytest.fixture
def recommender_insights(gcp):
    gcp.recommender.insights = {
        'google.compute.image.IdleResourceInsight': [
            fakes.insight('//compute.googleapis.com/projects/web-prod/global/images/old-image', 'Image unused for 90 days')],
        'google.compute.disk.IdleResourceInsight': [
            fakes.insight('//compute.googleapis.com/projects/web-prod/zones/us-central1-a/disks/orphan-disk', 'Disk detached for 30 days'),
            fakes.insight(None, 'Insight without a target resource')],
        'google.cloudsql.instance.IdleInsight': [
            fakes.insight('//sqladmin.googleapis.com/projects/data-lake/instances/reporting-db', 'Instance idle for 14 days')],
    }
    return gcp.recommender


def test_insights(legacy_client, client, insight_scope, recommender_insights):
    response = assert_parity(legacy_client, client, 'POST', '/api/get-insights', json={'scope': 'folder', 'scope_id': '42'})
    assert response.status_code == 200
    insights = response.get_json()
    assert {'check': 'Idle Images', 'project': 'web-prod', 'resource': 'old-image', 'details': 'Image unused for 90 days'} in insights
    assert {'check': 'Idle Disks', 'project': 'data-lake', 'resource': 'N/A', 'details': 'Insight without a target resource'} in insights
    legacy_parents, parents = halves(recommender_insights.parents)
    assert parents == legacy_parents
    # Per project: 1 global insight type, 2 regional x 2 regions, 8 zonal x 2 zones.
    assert len(parents) == len(INSIGHT_PROJECTS) * (1 + 2 * 2 + 8 * 2)


def test_insight_type_errors_are_skipped(legacy_client, client, insight_scope, recommender_insights):
    recommender_insights.errors['google.compute.image.IdleResourceInsight'] = PermissionDenied('recommender.computeImageIdleResourceInsights.list')
    response = assert_parity(legacy_client, client, 'POST', '/api/get-insights', json={'scope': 'folder', 'scope_id': '42'})
    assert response.status_code == 200
    assert not any(insight['check'] == 'Idle Images' for insight in response.get_json())


def test_insights_without_projects(legacy_client, client, insight_scope, recommender_insights):
    insight_scope.clear()
    response = assert_parity(legacy_client, client, 'POST', '/api/get-insights', json={'scope': 'project', 'scope_id': 'p1'})
    assert (response.status_code, response.get_json()) == (200, [])
    assert recommender_insights.parents == []


def test_insights_project_listing_error(legacy_client, client, legacy, monkeypatch):
    def fail(scope, scope_id):
        raise RuntimeError('Cloud Asset API has not been used in project test-project')
    for module in (legacy, insights_service):
        monkeypatch.setattr(module, 'list_projects_for_scope', fail)
    response = assert_parity(legacy_client, client, 'POST', '/api/get-insights', json={'scope': 'folder', 'scope_id': '42'})
    assert response.status_code == 500
    assert response.get_json() == {
        'error': 'An internal error occurred while fetching insights: Cloud Asset API has not been used in project test-project'}


@pytest.mark.parametrize('body', [{'scope': 'folder'}, {'scope_id': '42'}, {}])
def test_insights_require_scope_and_id(body, legacy_client, client):
    response = assert_parity(legacy_client, client, 'POST', '/api/get-insights', json=body)
    assert response.status_code == 400
    assert response.get_json() == {'error': 'Scope and Scope ID are required.'}


# --- /api/get-summary ---

CSV_REPORT = 'Organization Policies\r\nCategory,Policy,Expected Value,Current Value,Status\r\n'


def test_summary(legacy_client, client, gcp):
    gcp.bucket.put('job-1/p1_report.csv', CSV_REPORT, 'text/csv')
    gcp.gemini.reply = '**Overall:** a solid baseline.\n\n* Opportunity to Enhance Data Security'
    response = assert_parity(legacy_client, client, 'POST', '/api/get-summary', json={'scope_id': 'p1', 'job_id': 'job-1'})
    assert response.status_code == 200
    assert response.get_json() == {'summary': gcp.gemini.reply}
    (legacy_prompt,), (prompt,) = halves(gcp.gemini.prompts)
    assert prompt[1] == legacy_prompt[1]
    assert CSV_REPORT in prompt[1]
    # New: GEMINI_MODEL=auto picks the newest stable Flash model instead of the hardcoded one.
    assert (legacy_prompt[0], prompt[0]) == ('gemini-2.5-flash', fakes.FakeGemini.NEWEST_STABLE_FLASH)
    assert gcp.gemini.inits == [('test-project', 'global')]
    assert set(gcp.gemini.clients) == {('test-project', 'global')}


def test_summary_without_a_csv_report(legacy_client, client, gcp):
    response = assert_parity(legacy_client, client, 'POST', '/api/get-summary', json={'scope_id': 'p1', 'job_id': 'job-1'})
    assert response.status_code == 404
    assert response.get_json() == {'error': 'CSV report not found. Cannot generate summary.'}
    assert gcp.gemini.prompts == []


def test_summary_speaks_of_the_scope_the_page_sends(client, gcp):
    """New (v15.3): the report page sends its scope with the request, and a folder or project scan's summary
    opens on the folder or project. Without a scope (``test_summary``: the legacy request) the prompt is legacy's."""
    gcp.bucket.put('job-1/42_report.csv', CSV_REPORT, 'text/csv')
    gcp.gemini.reply = 'summary'
    response = client.post('/api/get-summary', json={'scope': 'folder', 'scope_id': '42', 'job_id': 'job-1'})
    assert response.status_code == 200 and response.get_json() == {'summary': 'summary'}
    (_, prompt), = gcp.gemini.prompts
    assert "summarizes the overall state of the folder's cloud environment." in prompt
    assert "organization's cloud environment" not in prompt


def test_summary_gemini_error(legacy_client, client, gcp):
    gcp.bucket.put('job-1/p1_report.csv', CSV_REPORT, 'text/csv')
    gcp.gemini.error = RuntimeError('404 Publisher Model gemini-2.5-flash was not found')
    response = assert_parity(legacy_client, client, 'POST', '/api/get-summary', json={'scope_id': 'p1', 'job_id': 'job-1'})
    assert response.status_code == 500
    assert response.get_json() == {'error': 'An internal error occurred while generating the AI summary.'}


@pytest.mark.parametrize('body', [{'scope_id': 'p1'}, {'job_id': 'job-1'}, {}])
def test_summary_requires_scope_and_job_ids(body, legacy_client, client):
    response = assert_parity(legacy_client, client, 'POST', '/api/get-summary', json=body)
    assert response.status_code == 400
    assert response.get_json() == {'error': 'Scope ID and Job ID are required.'}


def test_gemini_model_and_location_come_from_settings(gcp, env, monkeypatch):
    """New: GEMINI_MODEL pins a model and VERTEX_LOCATION replaces the hardcoded "global" (still the default)."""
    monkeypatch.setenv('GEMINI_MODEL', 'gemini-replacement-model')
    monkeypatch.setenv('VERTEX_LOCATION', 'us-central1')
    gcp.bucket.put('job-1/p1_report.csv', CSV_REPORT, 'text/csv')
    http = create_app().test_client()
    assert http.post('/api/get-summary', json={'scope_id': 'p1', 'job_id': 'job-1'}).status_code == 200
    findings = [{'index': 0, 'finding_text': 'Bucket public-assets is publicly readable', 'project_id': 'data-lake'}]
    assert http.post('/api/get-suggestions', json={'findings': findings}).status_code == 200
    assert [model for model, _ in gcp.gemini.prompts] == ['gemini-replacement-model'] * 2
    assert set(gcp.gemini.clients) == {('test-project', 'us-central1')}
    assert gcp.gemini.list_calls == 0  # a pinned model needs no lookup


# --- /api/get-suggestions ---

FINDINGS = [
    {'index': 0, 'finding_text': 'Firewall rule allow-all is open to 0.0.0.0/0', 'project_id': 'web-prod'},
    {'index': 3, 'finding_text': 'Bucket public-assets is publicly readable', 'project_id': 'data-lake'},
    {'index': 7, 'finding_text': 'Key for sa-legacy is 400 days old', 'project_id': 'web-prod'},
]


def gemini_reply(prompt):
    """A reply that depends only on the prompt, so the order of the concurrent calls doesn't matter."""
    if "'data-lake'" in prompt:
        return 'I cannot help with that.'
    if 'allow-all' in prompt:
        return '  gcloud compute firewall-rules delete allow-all --project=web-prod\n'
    return 'gcloud iam service-accounts keys delete KEY_ID --iam-account=sa-legacy@web-prod.iam.gserviceaccount.com'


def test_suggestions(legacy_client, client, gcp):
    gcp.gemini.reply = gemini_reply
    response = assert_parity(legacy_client, client, 'POST', '/api/get-suggestions', json={'findings': FINDINGS})
    assert response.status_code == 200
    assert response.get_json() == {
        'finding-0': 'gcloud compute firewall-rules delete allow-all --project=web-prod',
        'finding-3': 'AI could not generate a valid command.',
        'finding-7': 'gcloud iam service-accounts keys delete KEY_ID --iam-account=sa-legacy@web-prod.iam.gserviceaccount.com',
    }
    legacy_prompts, prompts = halves(gcp.gemini.prompts)
    assert sorted(text for _, text in prompts) == sorted(text for _, text in legacy_prompts)  # the calls run concurrently
    assert {model for model, _ in legacy_prompts} == {'gemini-2.5-flash'}
    assert {model for model, _ in prompts} == {fakes.FakeGemini.NEWEST_STABLE_FLASH}
    assert gcp.gemini.inits == [('test-project', 'global')] * 3
    assert gcp.gemini.list_calls == 1  # the concurrent calls share one lookup


@pytest.mark.parametrize('body', [{'findings': []}, {}])
def test_suggestions_without_findings(body, legacy_client, client, gcp):
    response = assert_parity(legacy_client, client, 'POST', '/api/get-suggestions', json=body)
    assert (response.status_code, response.get_json()) == (200, {})
    assert gcp.gemini.prompts == []


def test_suggestions_gemini_error(legacy_client, client, gcp):
    gcp.gemini.error = RuntimeError('500 Internal error')
    response = assert_parity(legacy_client, client, 'POST', '/api/get-suggestions', json={'findings': FINDINGS[:2]})
    assert response.get_json() == {'finding-0': 'Error generating remediation command.',
                                   'finding-3': 'Error generating remediation command.'}


def test_suggestions_rate_limit(legacy_client, client, gcp, monkeypatch):
    sleeps = []
    monkeypatch.setattr(time, 'sleep', sleeps.append)
    message = 'Quota exceeded for aiplatform.googleapis.com/generate_content_requests'
    gcp.gemini.error = ResourceExhausted(message)  # what vertexai raises (legacy)
    gcp.gemini.genai_error = genai_errors.ClientError(  # what google-genai raises (new)
        429, {'error': {'code': 429, 'status': 'RESOURCE_EXHAUSTED', 'message': message}})
    response = assert_parity(legacy_client, client, 'POST', '/api/get-suggestions', json={'findings': FINDINGS[:1]})
    assert response.get_json() == {'finding-0': 'Error: API rate limit exceeded.'}
    assert len(gcp.gemini.prompts) == 3 * 2  # three attempts each
    assert [int(delay) for delay in sleeps] == [2, 4] * 2  # exponential backoff plus up to 1 s of jitter


def test_suggestions_malformed_finding(legacy_client, client):
    findings = [{'finding_text': 'no index', 'project_id': 'web-prod'}]
    response = assert_parity(legacy_client, client, 'POST', '/api/get-suggestions', json={'findings': findings})
    assert response.status_code == 500
    assert response.get_json() == {'error': 'An internal error occurred on the server.'}


# --- Malformed request bodies ---

@pytest.mark.parametrize('path', ['/api/get-insights', '/api/get-summary', '/api/get-suggestions'])
@pytest.mark.parametrize('kwargs', [
    {'data': 'scope=folder', 'content_type': 'application/x-www-form-urlencoded'},  # not JSON
    {'data': '{"scope": ', 'content_type': 'application/json'},  # invalid JSON
    {'json': ['folder', '42']},  # JSON, but not an object
    {'data': 'null', 'content_type': 'application/json'},
])
def test_malformed_json_bodies(path, kwargs, legacy_client, client):
    """Whatever the error (415, 400 or 500, JSON or an HTML error page), it is the legacy one."""
    response = assert_parity(legacy_client, client, 'POST', path, html=True, **kwargs)
    assert response.status_code >= 400
