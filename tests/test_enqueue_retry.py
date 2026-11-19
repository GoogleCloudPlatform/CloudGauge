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
"""v20 — enqueueing a scan when Cloud Tasks falters (the GA work plan's A1).

Production saw one ``503 Stream removed`` from ``create_task`` reach a person as a 500. Now every ``create_task`` carries
``app.services.tasks.ENQUEUE_RETRY`` (UNAVAILABLE, DEADLINE_EXCEEDED and INTERNAL retried with backoff for up to thirty
seconds), the scan task is named after its job so the retry can never start a scan twice, and what still fails is a
**503 "Scan not queued"** page (JSON for a client that asks for it; ``/scheduled-scan`` likewise) that notes nothing and
starts nothing — the next attempt is a fresh start.
"""
import json
import re

import pytest
from google.api_core.exceptions import (AlreadyExists, DeadlineExceeded, InternalServerError, InvalidArgument, NotFound,
                                        PermissionDenied, RetryError, ServiceUnavailable)

import fakes
from app.services import schedules, tasks
from helpers import make_settings

FORM = {'scope': 'project', 'scope_id': 'web-prod'}
JOB = '0f8fad5b-d9cb-469f-a165-70867728950e'


@pytest.fixture
def fast_retry(monkeypatch):
    """The production retry with millisecond pauses and a short timeout: the same predicate, a test that takes no time."""
    fast = tasks.ENQUEUE_RETRY.with_delay(initial=0.001, maximum=0.002).with_timeout(0.2)
    monkeypatch.setattr(tasks, 'ENQUEUE_RETRY', fast)
    return fast


# --- The retry itself ---

def test_the_retry_covers_transient_answers_only():
    predicate = tasks.ENQUEUE_RETRY._predicate
    assert all(predicate(error('x')) for error in (ServiceUnavailable, DeadlineExceeded, InternalServerError))
    assert not any(predicate(error('x')) for error in (PermissionDenied, NotFound, InvalidArgument, AlreadyExists))
    assert (tasks.ENQUEUE_RETRY._initial, tasks.ENQUEUE_RETRY._maximum, tasks.ENQUEUE_RETRY._multiplier) == (1.0, 8.0, 2.0)
    assert tasks.ENQUEUE_RETRY.timeout == 30.0


def test_transient_answers_are_retried_and_the_scan_task_is_named_after_its_job(gcp, fast_retry):
    gcp.tasks.create_task_errors = [ServiceUnavailable('503 Stream removed'), DeadlineExceeded('deadline')]
    created = tasks.enqueue_scan(make_settings(), fakes.WORKER_URL, 'project', 'web-prod', JOB, client=gcp.tasks)
    assert gcp.tasks.create_task_attempts == 3 and gcp.tasks.retries == [fast_retry]
    ((parent, task),) = gcp.tasks.tasks
    assert created.name == task['name'] == f'{parent}/tasks/scan-{JOB}'
    assert json.loads(task['http_request']['body']) == {'scope': 'project', 'scope_id': 'web-prod', 'job_id': JOB}


def test_a_second_creation_of_the_same_scan_task_is_not_a_second_scan(gcp):
    """The retry after a lost answer: Cloud Tasks already has the task, so the second create is AlreadyExists — counted
    as created, and the queue holds one task."""
    settings = make_settings()
    assert tasks.enqueue_scan(settings, fakes.WORKER_URL, 'project', 'web-prod', JOB, client=gcp.tasks) is not None
    assert tasks.enqueue_scan(settings, fakes.WORKER_URL, 'project', 'web-prod', JOB, client=gcp.tasks) is None
    assert len(gcp.tasks.tasks) == 1 and gcp.tasks.task_ids() == [f'scan-{JOB}']


def test_an_answer_that_is_not_transient_is_not_retried(gcp, fast_retry):
    gcp.tasks.create_task_errors = [PermissionDenied('cloudtasks.tasks.create denied')]
    with pytest.raises(PermissionDenied):
        tasks.enqueue_scan(make_settings(), fakes.WORKER_URL, 'project', 'web-prod', JOB, client=gcp.tasks)
    assert gcp.tasks.create_task_attempts == 1 and gcp.tasks.tasks == []


def test_the_retry_gives_up_after_its_timeout_with_the_last_answer_as_the_cause(gcp, fast_retry):
    gcp.tasks.create_task_errors = [ServiceUnavailable('503 Stream removed')] * 10_000
    with pytest.raises(RetryError) as raised:
        tasks.enqueue_scan(make_settings(), fakes.WORKER_URL, 'project', 'web-prod', JOB, client=gcp.tasks)
    assert isinstance(raised.value.cause, ServiceUnavailable) and gcp.tasks.create_task_attempts > 1
    assert gcp.tasks.tasks == []
    assert schedules.not_queued_answer(raised.value) == 'retried for 0 s: 503 Stream removed'


def test_the_fan_out_tasks_carry_the_same_retry(gcp):
    settings = make_settings()
    assert tasks.enqueue_task(settings, fakes.WORKER_URL, '/sweep', {'job_id': JOB, 'sweep': 1}, task_id=f'{JOB}-sweep-1', client=gcp.tasks)
    assert not tasks.enqueue_task(settings, fakes.WORKER_URL, '/sweep', {'job_id': JOB, 'sweep': 1}, task_id=f'{JOB}-sweep-1', client=gcp.tasks)
    assert gcp.tasks.retries == [tasks.ENQUEUE_RETRY, tasks.ENQUEUE_RETRY]


@pytest.mark.parametrize('error, expected', [
    (ServiceUnavailable('Stream removed'), '503 Stream removed'),
    (PermissionDenied('403 POST https://cloudtasks.googleapis.com/...: denied'), '403 POST https://cloudtasks.googleapis.com/...: denied'),
    (RetryError('Deadline of 30.0s exceeded', cause=InternalServerError('internal\n  error')), 'retried for 30 s: 500 internal error'),
    (RetryError('Deadline of 30.0s exceeded', cause=None), 'Deadline of 30.0s exceeded'),
])
def test_the_answer_is_one_line(error, expected):
    assert schedules.not_queued_answer(error) == expected


# --- POST /scan ---

def test_a_scan_that_cannot_be_queued_is_a_503_page_that_offers_to_try_again(testing_app, gcp, fast_retry, caplog):
    http = testing_app.test_client()
    gcp.tasks.create_task_errors = [ServiceUnavailable('503 Stream removed')] * 10_000
    response = http.post('/scan', data=FORM)
    page = response.get_data(as_text=True)
    assert response.status_code == 503 and response.headers['Retry-After'] == '60'
    assert 'Scan not queued' in page and 'project web-prod' in page and 'nothing was started' in page
    assert 'test-queue' in page and 'retried for 0 s: 503 Stream removed' in page and 'Traceback' not in page
    # The button submits the same scan again; the link goes back to the form.
    assert re.search(r'<form method="post" action="/scan">.*?name="scope" value="project".*?name="scope_id" value="web-prod".*?Try again', page, re.S)
    assert 'href="/"' in page and 'Back to the form' in page
    assert gcp.tasks.tasks == [] and 'schedules/project/web-prod.json' not in gcp.bucket.objects  # nothing started, nothing noted
    assert 'could not be queued on test-queue: retried for 0 s: 503 Stream removed' in caplog.text


def test_the_503_is_json_for_a_client_that_asks_for_it(testing_app, gcp, fast_retry):
    http = testing_app.test_client()
    gcp.tasks.create_task_errors = [InternalServerError('internal')] * 10_000
    response = http.post('/scan', data=FORM, headers={'Accept': 'application/json'})
    assert response.status_code == 503 and response.headers['Retry-After'] == '60'
    assert response.get_json() == {'error': schedules.NOT_QUEUED_MESSAGE, 'queue': 'test-queue', 'answer': 'retried for 0 s: 500 internal'}


def test_after_a_503_the_next_attempt_starts_the_scan(testing_app, gcp, fast_retry):
    """Nothing was noted for the scope, so the person's "Try again" is a fresh start, not a 409."""
    http = testing_app.test_client()
    gcp.tasks.create_task_errors = [ServiceUnavailable('down')] * 10_000
    assert http.post('/scan', data=FORM).status_code == 503
    gcp.tasks.create_task_errors = [ServiceUnavailable('one more'), ServiceUnavailable('and another')]  # then it takes the task
    again = http.post('/scan', data=FORM)
    assert again.status_code == 302
    job_id = again.headers['Location'].split('/')[2]
    assert gcp.tasks.task_ids() == [f'scan-{job_id}']
    assert json.loads(gcp.bucket.objects['schedules/project/web-prod.json'][0])['job_id'] == job_id
    assert http.post('/scan', data=FORM).status_code == 409  # and now the scope is taken, as before


# --- /scheduled-scan ---

def test_a_scheduled_scan_that_cannot_be_queued_is_a_503_for_cloud_scheduler(testing_app, gcp, fast_retry, caplog):
    http = testing_app.test_client()
    gcp.tasks.create_task_errors = [ServiceUnavailable('503 Stream removed')] * 10_000
    response = http.post('/scheduled-scan', json={'scope': 'project', 'scope_id': 'web-prod', 'name': 'weekly'})
    assert response.status_code == 503 and response.headers['Retry-After'] == '60'
    assert response.get_json() == {'error': schedules.NOT_QUEUED_MESSAGE, 'schedule': 'weekly', 'queue': 'test-queue',
                                   'answer': 'retried for 0 s: 503 Stream removed'}
    assert gcp.tasks.tasks == [] and 'schedules/project/web-prod.json' not in gcp.bucket.objects
    assert "scheduled scan 'weekly' of project web-prod could not be queued" in caplog.text
    # The job's next run (the deployments create it without retries) finds the scope free.
    gcp.tasks.create_task_errors = []
    assert http.post('/scheduled-scan', json={'scope': 'project', 'scope_id': 'web-prod', 'name': 'weekly'}).status_code == 202
