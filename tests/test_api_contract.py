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
"""The HTTP contract of the web routes: what each request gets back, and what it makes the app do.

Every test sends its request to ``client`` (``create_app()`` in the production
profile, as gunicorn runs it) and pins the response — status, content type,
body — and the calls the app made against the GCP fakes. The index and status
pages are pinned on what they tell the browser (``page_facts``); everything
else literally. Formerly the parity suite, which sent the same requests to the
pre-refactor module and compared: the expectations it established are written
out here, so this module is the specification. ``/run-scan`` is covered by
test_worker.py.
"""
import json
import time
import uuid
from datetime import timedelta
from urllib.parse import quote

import pytest
from google.api_core.exceptions import PermissionDenied
from google.cloud import tasks_v2
from google.genai import errors as genai_errors

import fakes
from app import create_app
from app.services import insights as insights_service
from helpers import normalized_lines, page_facts

SA_EMAIL = fakes.TEST_ENV['SERVICE_ACCOUNT_EMAIL']
XSS = '"><img src=x onerror=alert(1)>'  # no "/": a URL segment can't contain one
# v18.6.1: the app validates every identifier (app.validation) — the requests use a real job ID shape and a real
# project ID; the malformed-input tests below assert the 400 where the pre-refactor app answered 200, 415 or 500.
JOB = '11111111-1111-4111-8111-111111111111'
P1 = 'proj-one'
CLOUD_PLATFORM = 'https://www.googleapis.com/auth/cloud-platform'


# --- Pages ---

def test_index_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert response.mimetype == 'text/html'
    assert page_facts(response.get_data(as_text=True)) == {
        'forms': [('/scan', 'post')],
        'fields': [('scope', False, False), ('scope_id', True, True)],  # the resource select waits for a scope
        'options': ['', 'organization', 'folder', 'project', ''],
        'submit_disabled': True,
        'constants': [],
        'urls': ['/api/list-resources?scope=${selectedScope}'],
    }


def test_scan_enqueues_the_task(client, gcp, monkeypatch):
    """One Cloud Tasks task per scan, in the configured queue: a POST of the scope and the job ID to the worker's
    ``/run-scan`` with an OIDC token of the service account, a 30-minute dispatch deadline (without one Cloud Tasks
    retried a scan still running after 10 minutes) and the job's name (v20: the retry of a transient Cloud Tasks
    answer cannot start the scan twice). The browser is sent to the status page."""
    job_id = uuid.UUID('0f8fad5b-d9cb-469f-a165-70867728950e')
    monkeypatch.setattr(uuid, 'uuid4', lambda: job_id)
    response = client.post('/scan', data={'scope': 'folder', 'scope_id': '42'})
    assert response.status_code == 302
    assert response.headers['Location'] == f'/status/{job_id}/folder/42'

    ((parent, task),) = gcp.tasks.tasks
    assert parent == 'projects/test-project/locations/us-central1/queues/test-queue'
    assert set(task) == {'http_request', 'dispatch_deadline', 'name'}
    assert task['dispatch_deadline'] == timedelta(minutes=30)
    assert task['name'] == f'{parent}/tasks/scan-{job_id}'
    request = task['http_request']
    assert set(request) == {'http_method', 'url', 'headers', 'oidc_token', 'body'}
    assert request['http_method'] == tasks_v2.HttpMethod.POST
    assert request['url'] == f'{fakes.WORKER_URL}/run-scan'
    assert request['headers'] == {'Content-Type': 'application/json'}
    assert request['oidc_token'] == {'service_account_email': SA_EMAIL}
    assert json.loads(request['body']) == {'scope': 'folder', 'scope_id': '42', 'job_id': str(job_id)}


@pytest.mark.parametrize('kwargs', [
    {'data': {'scope': 'project', 'scope_id': ''}},
    {'data': {'scope': '', 'scope_id': P1}},
    {'data': {'scope': 'project'}},  # no scope_id field
    {'data': {}},
    {'json': {'scope': 'project', 'scope_id': P1}},  # JSON instead of a form
    {'data': {'scope': 'team', 'scope_id': P1}},  # v18.6.1: not a scope
    {'data': {'scope': 'project', 'scope_id': 'p1'}},  # v18.6.1: not a project ID
    {'data': {'scope': 'folder', 'scope_id': 'not-a-number'}},
])
def test_scan_rejects_incomplete_forms(kwargs, client, gcp):
    """400 to a missing field and, since v18.6.1, to any scope or scope ID that is not one (app.validation) — the
    message names the field, and no task is enqueued (the pre-refactor app accepted the last three and enqueued a scan)."""
    response = client.post('/scan', **kwargs)
    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith(('scope', 'scope_id'))
    assert gcp.tasks.tasks == []


def test_status_page(client, gcp):
    """The status page's contract: the constants it embeds, where it polls, where the report is — and, since v16.1,
    its Download CSV is the web service's route, where the pre-refactor page embedded a one-hour signed Cloud Storage
    URL (``signed_csv_url``) minted on every page load: the page signs nothing and fetches no credential."""
    startup_auth_calls = len(gcp.auth_scopes)  # the app's startup looked up its URL
    response = client.get(f'/status/{JOB}/organization/123456789')
    assert response.status_code == 200
    assert response.mimetype == 'text/html'
    page = response.get_data(as_text=True)
    assert page_facts(page) == {
        'forms': [], 'fields': [], 'options': [], 'submit_disabled': False,
        'constants': [('job_id', f'"{JOB}"'), ('scope_id', '"123456789"')],
        'urls': ['/api/status/${job_id}/${scope_id}', '/report/${job_id}/${scope_id}', '/report/${job_id}/${scope_id}/csv'],
    }
    assert 'const scope = "organization";' in normalized_lines(page)  # v14.2: the card names the scope
    assert 'signed_csv_url' not in page
    assert gcp.bucket.signed_url_requests == []
    assert gcp.auth_scopes[startup_auth_calls:] == []


def test_status_page_refuses_malformed_url_values(client):
    """Since v18.6.1 a job ID that is not a UUID or a scope ID that is not one gets a 400 (app.validation) — nothing of
    the value reaches a page (the pre-refactor page escaped whatever the URL carried into its constants)."""
    path = f'/status/{quote(XSS, safe="")}/project/{quote(XSS, safe="")}'
    response = client.get(path)
    assert response.status_code == 400
    assert XSS not in response.get_data(as_text=True) and response.get_data(as_text=True) == 'job_id must be a UUID.'
    assert client.get(f'/status/{JOB}/project/{quote(XSS, safe="")}').get_data(as_text=True).startswith('scope_id must be a project ID')
    assert client.get(f'/status/{JOB}/team/{P1}').get_data(as_text=True) == 'scope must be organization, folder or project.'


def test_report_is_served_as_stored(client, gcp):
    stored = '<!DOCTYPE html>\n<html><body>CloudGauge Report: Project proj-one &amp; more</body></html>\n'
    gcp.bucket.put(f'{JOB}/{P1}_report.html', stored, 'text/html')
    response = client.get(f'/report/{JOB}/{P1}')
    assert response.status_code == 200
    assert response.mimetype == 'text/html'
    assert response.get_data(as_text=True) == stored


def test_missing_report(client):
    response = client.get(f'/report/{JOB}/{P1}')
    assert (response.status_code, response.get_data(as_text=True)) == (404, 'Report not found or is still generating.')
    assert response.mimetype == 'text/html'


def test_report_storage_error(client, gcp):
    gcp.bucket.error = RuntimeError('503 Service Unavailable')
    response = client.get(f'/report/{JOB}/{P1}')
    assert (response.status_code, response.get_data(as_text=True)) == (500, 'Could not retrieve report.')
    assert response.mimetype == 'text/html'


# --- /api/status ---

def test_status_is_pending_before_the_worker_starts(client):
    response = client.get(f'/api/status/{JOB}/{P1}')
    assert (response.status_code, response.mimetype) == (200, 'application/json')
    assert response.get_json() == {'status': 'pending', 'progress': 0, 'current_task': 'Waiting for task to start...'}


def test_status_is_read_from_the_bucket(client, gcp):
    status = {'job_id': JOB, 'scope_id': P1, 'progress': 35, 'current_task': '(5/14) Finished: GKE Hygiene',
              'status': 'running', 'timestamp': '2026-09-29T10:00:00+00:00'}
    gcp.bucket.put(f'{JOB}/{P1}_status.json', json.dumps(status), 'application/json')
    response = client.get(f'/api/status/{JOB}/{P1}')
    assert (response.status_code, response.mimetype) == (200, 'application/json')
    assert response.get_json() == status


def test_status_storage_error(client, gcp):
    gcp.bucket.error = RuntimeError('503 Service Unavailable')
    response = client.get(f'/api/status/{JOB}/{P1}')
    assert (response.status_code, response.mimetype) == (500, 'application/json')
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


def test_list_resources_organization(client, org_resources):
    response = client.get('/api/list-resources?scope=organization')
    assert (response.status_code, response.mimetype) == (200, 'application/json')
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
    siblings; a parent outside the account's view starts the path lower."""
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


def test_list_resources_requires_a_scope(client, gcp):
    startup_calls = list(gcp.discovery.calls)
    response = client.get('/api/list-resources')
    assert (response.status_code, response.mimetype) == (400, 'application/json')
    assert response.get_json() == {'error': 'Scope parameter is required'}
    assert gcp.discovery.calls == startup_calls  # rejected before the ancestry lookup


def test_list_resources_rejects_an_unknown_scope(client):
    response = client.get('/api/list-resources?scope=billing-account')
    assert (response.status_code, response.mimetype) == (400, 'application/json')
    assert response.get_json() == {'error': 'Invalid scope'}


def test_list_resources_asset_api_error(client, gcp):
    gcp.assets.error = PermissionDenied('cloudasset.assets.searchAllResources')
    response = client.get('/api/list-resources?scope=folder')
    assert (response.status_code, response.mimetype) == (500, 'application/json')
    assert response.get_json() == {'error': f'Failed to list resources: {gcp.assets.error}'}


@pytest.mark.parametrize('break_ancestry', ['no organization', 'error'])
def test_list_resources_without_a_parent_organization(break_ancestry, client, gcp):
    if break_ancestry == 'error':
        gcp.discovery.ancestry_error = RuntimeError('resourcemanager.projects.get denied')
    else:
        gcp.discovery.ancestry = {'ancestor': [{'resourceId': {'type': 'project', 'id': 'test-project'}}]}
    response = client.get('/api/list-resources?scope=project')
    assert (response.status_code, response.mimetype) == (500, 'application/json')
    assert response.get_json() == {'error': 'Could not determine parent organization'}


# --- /api/get-insights ---

INSIGHT_PROJECTS = [{'projectId': 'web-prod', 'displayName': 'Web Prod'}, {'projectId': 'data-lake', 'displayName': 'Data Lake'}]
INSIGHT_LOCATIONS = (['us-central1-a', 'europe-west1-b'], ['us-central1', 'global'])


@pytest.fixture
def insight_scope(monkeypatch):
    """The projects and locations the insights service sees. Returns the project list; clear it for "no projects"."""
    projects = list(INSIGHT_PROJECTS)
    monkeypatch.setattr(insights_service, 'list_projects_for_scope', lambda scope, scope_id: projects)
    monkeypatch.setattr(insights_service, 'get_active_compute_locations', lambda all_projects, on_error=None: INSIGHT_LOCATIONS)
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


def test_insights(client, insight_scope, recommender_insights):
    response = client.post('/api/get-insights', json={'scope': 'folder', 'scope_id': '42'})
    assert (response.status_code, response.mimetype) == (200, 'application/json')
    insights = response.get_json()
    assert {'check': 'Idle Images', 'project': 'web-prod', 'resource': 'old-image', 'details': 'Image unused for 90 days'} in insights
    assert {'check': 'Idle Disks', 'project': 'data-lake', 'resource': 'N/A', 'details': 'Insight without a target resource'} in insights
    parents = recommender_insights.parents
    # Per project: 1 global insight type, 2 regional x 2 regions, 8 zonal x 2 zones — each asked for under its location.
    assert len(parents) == len(INSIGHT_PROJECTS) * (1 + 2 * 2 + 8 * 2)
    assert {parent.split('/')[1] for parent in parents} == {'web-prod', 'data-lake'}
    assert {parent.split('/')[3] for parent in parents} == {'us-central1-a', 'europe-west1-b', 'us-central1', 'global'}
    assert all(parent.split('/')[4] == 'insightTypes' for parent in parents)


def test_insight_type_errors_are_skipped(client, insight_scope, recommender_insights):
    recommender_insights.errors['google.compute.image.IdleResourceInsight'] = PermissionDenied('recommender.computeImageIdleResourceInsights.list')
    response = client.post('/api/get-insights', json={'scope': 'folder', 'scope_id': '42'})
    assert response.status_code == 200
    assert not any(insight['check'] == 'Idle Images' for insight in response.get_json())


def test_insights_without_projects(client, insight_scope, recommender_insights):
    insight_scope.clear()
    response = client.post('/api/get-insights', json={'scope': 'project', 'scope_id': P1})
    assert (response.status_code, response.get_json()) == (200, [])
    assert recommender_insights.parents == []


def test_insights_project_listing_error(client, monkeypatch):
    def fail(scope, scope_id):
        raise RuntimeError('Cloud Asset API has not been used in project test-project')
    monkeypatch.setattr(insights_service, 'list_projects_for_scope', fail)
    response = client.post('/api/get-insights', json={'scope': 'folder', 'scope_id': '42'})
    assert (response.status_code, response.mimetype) == (500, 'application/json')
    assert response.get_json() == {
        'error': 'An internal error occurred while fetching insights: Cloud Asset API has not been used in project test-project'}


@pytest.mark.parametrize('body, message', [
    ({'scope': 'folder'}, 'scope_id is required.'),
    ({'scope_id': '42'}, 'scope is required.'),
    ({}, 'scope is required.'),
    ({'scope': 'folder', 'scope_id': 'forty-two'}, "scope_id must be the folder's number."),  # v18.6.1
    ({'scope': 'organization', 'scope_id': '12/34'}, "scope_id must be the organization's number."),
])
def test_insights_require_scope_and_id(body, message, client):
    """400 to a missing field, naming what is wrong (since v18.6.1), and to a scope ID that is not one (which the
    pre-refactor app passed on to the Asset API)."""
    response = client.post('/api/get-insights', json=body)
    assert (response.status_code, response.mimetype) == (400, 'application/json')
    assert response.get_json() == {'error': message}


# --- /api/get-summary ---

CSV_REPORT = 'Organization Policies\r\nCategory,Policy,Expected Value,Current Value,Status\r\n'


def test_summary(client, gcp):
    """One prompt to Gemini, carrying the stored CSV; without a scope in the request it speaks of the organization.
    GEMINI_MODEL=auto picks the newest stable Flash model (the pre-refactor app hardcoded one)."""
    gcp.bucket.put(f'{JOB}/{P1}_report.csv', CSV_REPORT, 'text/csv')
    gcp.gemini.reply = '**Overall:** a solid baseline.\n\n* Opportunity to Enhance Data Security'
    response = client.post('/api/get-summary', json={'scope_id': P1, 'job_id': JOB})
    assert (response.status_code, response.mimetype) == (200, 'application/json')
    assert response.get_json() == {'summary': gcp.gemini.reply}
    ((model, prompt),) = gcp.gemini.prompts
    assert model == fakes.FakeGemini.NEWEST_STABLE_FLASH
    assert CSV_REPORT in prompt
    assert "summarizes the overall state of the organization's cloud environment." in prompt
    assert set(gcp.gemini.clients) == {('test-project', 'global')}


def test_summary_without_a_csv_report(client, gcp):
    response = client.post('/api/get-summary', json={'scope_id': P1, 'job_id': JOB})
    assert (response.status_code, response.mimetype) == (404, 'application/json')
    assert response.get_json() == {'error': 'CSV report not found. Cannot generate summary.'}
    assert gcp.gemini.prompts == []


def test_summary_speaks_of_the_scope_the_page_sends(client, gcp):
    """v15.3: the report page sends its scope with the request, and a folder or project scan's summary opens on the
    folder or project. Without a scope (``test_summary``) the prompt speaks of the organization."""
    gcp.bucket.put(f'{JOB}/42_report.csv', CSV_REPORT, 'text/csv')
    gcp.gemini.reply = 'summary'
    response = client.post('/api/get-summary', json={'scope': 'folder', 'scope_id': '42', 'job_id': JOB})
    assert response.status_code == 200 and response.get_json() == {'summary': 'summary'}
    (_, prompt), = gcp.gemini.prompts
    assert "summarizes the overall state of the folder's cloud environment." in prompt
    assert "organization's cloud environment" not in prompt


def test_summary_gemini_error(client, gcp):
    gcp.bucket.put(f'{JOB}/{P1}_report.csv', CSV_REPORT, 'text/csv')
    gcp.gemini.error = RuntimeError('404 Publisher Model gemini-2.5-flash was not found')
    response = client.post('/api/get-summary', json={'scope_id': P1, 'job_id': JOB})
    assert (response.status_code, response.mimetype) == (500, 'application/json')
    assert response.get_json() == {'error': 'An internal error occurred while generating the AI summary.'}


@pytest.mark.parametrize('body, message', [
    ({'scope_id': P1}, 'job_id is required.'),
    ({'job_id': JOB}, 'scope_id is required.'),
    ({}, 'job_id is required.'),
    ({'scope_id': P1, 'job_id': 'job-1'}, 'job_id must be a UUID.'),  # v18.6.1
    ({'scope_id': '../other', 'job_id': JOB}, 'scope_id must be an organization or folder number, or a project ID.'),
    ({'scope': 'project', 'scope_id': '42', 'job_id': JOB}, 'scope_id must be a project ID: 6-30 lower-case letters, digits and hyphens, starting with a letter.'),
])
def test_summary_requires_scope_and_job_ids(body, message, client, gcp):
    """400 to a missing ID and, since v18.6.1, to IDs that are not ones — before anything is read from the bucket."""
    response = client.post('/api/get-summary', json=body)
    assert (response.status_code, response.mimetype) == (400, 'application/json')
    assert response.get_json() == {'error': message}
    assert gcp.gemini.prompts == []


def test_gemini_model_and_location_come_from_settings(gcp, env, monkeypatch):
    """GEMINI_MODEL pins a model and VERTEX_LOCATION replaces the default "global"."""
    monkeypatch.setenv('GEMINI_MODEL', 'gemini-replacement-model')
    monkeypatch.setenv('VERTEX_LOCATION', 'us-central1')
    gcp.bucket.put(f'{JOB}/{P1}_report.csv', CSV_REPORT, 'text/csv')
    http = create_app().test_client()
    assert http.post('/api/get-summary', json={'scope_id': P1, 'job_id': JOB}).status_code == 200
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


def test_suggestions(client, gcp):
    """One prompt per finding (concurrently, sharing one model lookup), each naming the finding and its project; a
    reply that is not a gcloud command is reported as such; the answers are keyed ``finding-<index>``."""
    gcp.gemini.reply = gemini_reply
    response = client.post('/api/get-suggestions', json={'findings': FINDINGS})
    assert (response.status_code, response.mimetype) == (200, 'application/json')
    assert response.get_json() == {
        'finding-0': 'gcloud compute firewall-rules delete allow-all --project=web-prod',
        'finding-3': 'AI could not generate a valid command.',
        'finding-7': 'gcloud iam service-accounts keys delete KEY_ID --iam-account=sa-legacy@web-prod.iam.gserviceaccount.com',
    }
    prompts = gcp.gemini.prompts
    assert len(prompts) == len(FINDINGS)
    for finding in FINDINGS:  # the calls run concurrently: any order
        assert sum(f'"{finding["finding_text"]}"' in text and f"'{finding['project_id']}'" in text for _, text in prompts) == 1
    assert {model for model, _ in prompts} == {fakes.FakeGemini.NEWEST_STABLE_FLASH}
    assert gcp.gemini.list_calls == 1  # the concurrent calls share one lookup


@pytest.mark.parametrize('body', [{'findings': []}, {}])
def test_suggestions_without_findings(body, client, gcp):
    response = client.post('/api/get-suggestions', json=body)
    assert (response.status_code, response.get_json()) == (200, {})
    assert gcp.gemini.prompts == []


def test_suggestions_gemini_error(client, gcp):
    gcp.gemini.error = RuntimeError('500 Internal error')
    response = client.post('/api/get-suggestions', json={'findings': FINDINGS[:2]})
    assert response.status_code == 200
    assert response.get_json() == {'finding-0': 'Error generating remediation command.',
                                   'finding-3': 'Error generating remediation command.'}


def test_suggestions_rate_limit(client, gcp, monkeypatch):
    """A 429 from Gemini is retried twice with exponential backoff, then reported as the rate limit."""
    sleeps = []
    monkeypatch.setattr(time, 'sleep', sleeps.append)
    message = 'Quota exceeded for aiplatform.googleapis.com/generate_content_requests'
    gcp.gemini.genai_error = genai_errors.ClientError(  # what google-genai raises
        429, {'error': {'code': 429, 'status': 'RESOURCE_EXHAUSTED', 'message': message}})
    response = client.post('/api/get-suggestions', json={'findings': FINDINGS[:1]})
    assert response.status_code == 200
    assert response.get_json() == {'finding-0': 'Error: API rate limit exceeded.'}
    assert len(gcp.gemini.prompts) == 3  # three attempts
    assert [int(delay) for delay in sleeps] == [2, 4]  # exponential backoff plus up to 1 s of jitter


def test_suggestions_malformed_finding(client):
    """Since v18.6.1 the batch is validated first: 400 to a finding without an index, naming what is wrong, and no
    call to Gemini (the pre-refactor app answered 500)."""
    findings = [{'finding_text': 'no index', 'project_id': 'web-prod'}]
    response = client.post('/api/get-suggestions', json={'findings': findings})
    assert (response.status_code, response.mimetype) == (400, 'application/json')
    assert response.get_json() == {'error': "A finding's index must be a non-negative integer."}


# --- Malformed request bodies ---

@pytest.mark.parametrize('path', ['/api/get-insights', '/api/get-summary', '/api/get-suggestions'])
@pytest.mark.parametrize('kwargs', [
    {'data': 'scope=folder', 'content_type': 'application/x-www-form-urlencoded'},  # not JSON
    {'data': '{"scope": ', 'content_type': 'application/json'},  # invalid JSON
    {'json': ['folder', '42']},  # JSON, but not an object
    {'data': 'null', 'content_type': 'application/json'},
])
def test_malformed_json_bodies(path, kwargs, client):
    """Since v18.6.1 every JSON route answers one thing to a body that is not a JSON object: a 400 JSON error saying so
    (the pre-refactor app answered whatever werkzeug or the handler raised: 415, 400 or 500, JSON or an HTML error page)."""
    response = client.post(path, **kwargs)
    assert (response.status_code, response.mimetype) == (400, 'application/json')
    assert response.get_json() == {'error': 'The body must be a JSON object.'}
