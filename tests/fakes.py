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
"""In-memory stand-ins for the GCP clients the app uses. No network, no credentials.

``FakeGcp`` holds one of each and patches them in where the libraries are looked
up at call time. The legacy module and the new package reach GCP through
different import styles, and this way both talk to the same fakes.
"""
import copy
import json
from types import SimpleNamespace
from urllib.parse import quote

from google.genai import errors as genai_errors

TEST_ENV = {
    'PROJECT_ID': 'test-project',
    'LOCATION': 'us-central1',
    'TASK_QUEUE': 'test-queue',
    'RESULTS_BUCKET': 'test-bucket',
    'SERVICE_ACCOUNT_EMAIL': 'scanner@test-project.iam.gserviceaccount.com',
}
K_SERVICE = 'cloudgauge'  # the Cloud Run service name; Cloud Run sets K_SERVICE
WORKER_URL = 'https://cloudgauge-worker.example'
ORG_ID = '987654321'
ASSET_TYPES = {
    'folders': 'cloudresourcemanager.googleapis.com/Folder',
    'projects': 'cloudresourcemanager.googleapis.com/Project',
}


class FakeBlob:
    def __init__(self, bucket, name):
        self.bucket = bucket
        self.name = name

    def upload_from_string(self, data, content_type=None):
        self.bucket.check()
        self.bucket.objects[self.name] = (data, content_type)
        self.bucket.uploads.append((self.name, data, content_type))

    def download_as_text(self):
        self.bucket.check()
        data, _ = self.bucket.objects[self.name]
        return data.decode() if isinstance(data, bytes) else data

    def exists(self):
        self.bucket.check()
        return self.name in self.bucket.objects

    def generate_signed_url(self, **kwargs):
        if self.bucket.signing_error:
            raise self.bucket.signing_error
        self.bucket.signed_url_requests.append((self.name, kwargs))
        # Like google-cloud-storage, which percent-encodes the object name.
        return f'https://storage.example/{self.bucket.name}/{quote(self.name, safe="/~")}?X-Goog-Signature=abc&X-Goog-Expires=3600'

    @property
    def public_url(self):
        return f'https://storage.googleapis.com/{self.bucket.name}/{self.name}'


class FakeBucket:
    """Objects are listed in upload order, so both implementations read findings in the same order."""

    def __init__(self, name):
        self.name = name
        self.objects = {}
        self.uploads = []
        self.deleted = []
        self.signed_url_requests = []
        self.error = None  # raised by every read/write/list when set
        self.signing_error = None

    def check(self):
        if self.error:
            raise self.error

    def blob(self, name):
        return FakeBlob(self, name)

    def list_blobs(self, prefix=''):
        self.check()
        return [FakeBlob(self, name) for name in list(self.objects) if name.startswith(prefix)]

    def delete_blobs(self, blobs):
        for blob in blobs:
            self.objects.pop(blob.name, None)
            self.deleted.append(blob.name)

    def put(self, name, text, content_type='text/plain'):
        self.objects[name] = (text, content_type)

    def status_updates(self, job_id, scope_id):
        """The status documents written for a job, in order, without their timestamps."""
        key = f'{job_id}/{scope_id}_status.json'
        updates = []
        for name, data, content_type in self.uploads:
            if name == key:
                doc = json.loads(data)
                doc.pop('timestamp')
                updates.append((doc, content_type))
        return updates


class FakeStorageClient:
    def __init__(self):
        self.buckets = {}
        self.listings = {}  # project -> what list_buckets() returns (a list, or an exception to raise)
        self.project = None

    def for_project(self, project):
        """``storage.Client(project=...)``: the same buckets; ``list_buckets()`` lists ``project``'s."""
        if project is None:
            return self
        view = copy.copy(self)
        view.project = project
        return view

    def bucket(self, name):
        return self.buckets.setdefault(name, FakeBucket(name))

    def list_buckets(self):
        listing = self.listings.get(self.project, [])
        if isinstance(listing, Exception):
            raise listing
        return list(listing)


class FakeTasksClient:
    def __init__(self, create_queue_error=None, on_create_queue=None):
        self.tasks = []
        self.queues = []
        self.create_queue_error = create_queue_error
        self.on_create_queue = on_create_queue

    def queue_path(self, project, location, queue):
        return f'projects/{project}/locations/{location}/queues/{queue}'

    def create_task(self, parent, task):
        self.tasks.append((parent, task))
        return SimpleNamespace(name=f'{parent}/tasks/{len(self.tasks)}')

    def create_queue(self, parent, queue):
        self.queues.append((parent, queue))
        if self.on_create_queue:
            self.on_create_queue()
        if self.create_queue_error:
            raise self.create_queue_error


class FakeCredentials:
    token = 'fake-access-token'

    def refresh(self, request):
        pass


def _execute(result):
    """A request object whose execute() returns (or raises) ``result``."""
    def execute():
        if isinstance(result, Exception):
            raise result
        return result
    return SimpleNamespace(execute=execute)


class FakeDiscovery:
    """Replaces ``googleapiclient.discovery.build`` for the Cloud Run and Resource Manager calls."""

    def __init__(self, worker_url=WORKER_URL, org_id=ORG_ID):
        self.worker_url = worker_url  # None: the Cloud Run API response has no URL
        self.ancestry = {'ancestor': [{'resourceId': {'type': 'project', 'id': TEST_ENV['PROJECT_ID']}},
                                      {'resourceId': {'type': 'organization', 'id': org_id}}]}
        self.ancestry_error = None  # raised by getAncestry().execute() when set
        self.calls = []  # (serviceName, version) of every build()
        self.run_services = []  # the Cloud Run services looked up (full resource names)
        self.apis = {}  # serviceName -> the client that build() returns for other APIs (set by tests)

    def __call__(self, serviceName, version, **kwargs):
        self.calls.append((serviceName, version))
        if serviceName in self.apis:
            return self.apis[serviceName]
        if serviceName == 'run':
            services = SimpleNamespace(get=self._get_run_service)
            return SimpleNamespace(projects=lambda: SimpleNamespace(locations=lambda: SimpleNamespace(services=lambda: services)))
        if serviceName == 'cloudresourcemanager':
            return SimpleNamespace(projects=lambda: SimpleNamespace(getAncestry=self._get_ancestry))
        raise AssertionError(f'unexpected discovery.build({serviceName!r}, {version!r})')

    def _get_run_service(self, name):
        self.run_services.append(name)
        return _execute({'status': {'url': self.worker_url}})

    def _get_ancestry(self, projectId, body):
        return _execute(self.ancestry_error or self.ancestry)


class FakeGemini:
    """Stands in for Gemini in both implementations; records every prompt as ``(model, prompt)``.

    - Legacy: ``vertexai.init`` (``init``) and ``GenerativeModel`` (``model_class``).
    - New: ``app.services.gemini.get_client`` (``client``), a google-genai client
      whose ``models.list()`` returns ``models`` and ``models.generate_content()``
      replies like the legacy model does.
    """

    # What Vertex AI lists, in its order: old and preview models, Lite and specialized variants.
    MODELS = ['gemini-1.5-pro-002', 'gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-3-flash-preview',
              'gemini-3.5-flash', 'gemini-3.1-flash-image', 'gemini-3.5-flash-lite', 'gemini-3.8-flash',
              'gemini-3.7-flash', 'gemini-3.10-flash-preview', 'gemini-3.8-flash-cyber', 'gemini-live-2.5-flash-native-audio']
    NEWEST_STABLE_FLASH = 'gemini-3.8-flash'

    def __init__(self):
        self.reply = 'gcloud compute firewall-rules delete allow-all --project=test-project'
        self.error = None  # raised by both implementations
        self.genai_error = None  # raised by the google-genai client instead of ``error``, when set
        self.inits = []  # legacy vertexai.init() calls: (project, location)
        self.clients = []  # google-genai clients requested: (project, location)
        self.prompts = []
        self.models = [f'publishers/google/models/{model}' for model in self.MODELS]
        self.list_error = None
        self.list_calls = 0
        self.unavailable = set()  # models that generate_content() answers with 404

    def _generate(self, model, prompt, error):
        self.prompts.append((model, prompt))
        if error:
            raise error
        reply = self.reply(prompt) if callable(self.reply) else self.reply
        return SimpleNamespace(text=reply)

    def init(self, project=None, location=None, **kwargs):
        self.inits.append((project, location))

    @property
    def model_class(self):
        gemini = self

        class FakeGenerativeModel:
            def __init__(self, model_name):
                self.model_name = model_name

            def generate_content(self, prompt):
                return gemini._generate(self.model_name, prompt, gemini.error)

        return FakeGenerativeModel

    def client(self, project, location):
        self.clients.append((project, location))
        gemini = self

        class FakeModels:
            def list(self, config=None):
                gemini.list_calls += 1
                if gemini.list_error:
                    raise gemini.list_error
                return [SimpleNamespace(name=name) for name in gemini.models]

            def generate_content(self, *, model, contents, config=None):
                if model in gemini.unavailable:
                    gemini.prompts.append((model, contents))
                    raise genai_errors.ClientError(404, {'error': {'code': 404, 'status': 'NOT_FOUND', 'message': f'Publisher model {model} was not found'}})
                return gemini._generate(model, contents, gemini.genai_error or gemini.error)

        return SimpleNamespace(models=FakeModels())


class FakeAssets:
    """Replaces ``asset_v1.AssetServiceClient``; searches return the added resources of the requested types."""

    def __init__(self):
        self.resources = []
        self.error = None
        self.requests = []

    def add(self, kind, resource_id, display_name):
        """Adds a folder or a project (``kind`` is ``'folders'`` or ``'projects'``)."""
        self.resources.append(SimpleNamespace(
            name=f'//cloudresourcemanager.googleapis.com/{kind}/{resource_id}',
            display_name=display_name, asset_type=ASSET_TYPES[kind]))

    @property
    def client_class(self):
        assets = self

        class FakeAssetServiceClient:
            def __init__(self, *args, **kwargs):
                pass

            def search_all_resources(self, request):
                assets.requests.append(request)
                if assets.error:
                    raise assets.error
                return [r for r in assets.resources if r.asset_type in request['asset_types']]

        return FakeAssetServiceClient


def insight(target_resource, description):
    """A Recommender insight about ``target_resource`` (``None``: an insight without target resources)."""
    return SimpleNamespace(target_resources=[target_resource] if target_resource else [], description=description)


class FakeRecommender:
    """Replaces ``recommender_v1.RecommenderClient``: insights (or errors) by insight-type id."""

    def __init__(self):
        self.insights = {}
        self.errors = {}
        self.parents = []

    @property
    def client_class(self):
        recommender = self

        class FakeRecommenderClient:
            def __init__(self, *args, **kwargs):
                pass

            def list_insights(self, parent):
                recommender.parents.append(parent)
                insight_type = parent.rsplit('/', 1)[-1]
                if insight_type in recommender.errors:
                    raise recommender.errors[insight_type]
                return list(recommender.insights.get(insight_type, []))

        return FakeRecommenderClient


class FakeGcp:
    """One fake per GCP entry point the app uses; :meth:`install` patches them in."""

    def __init__(self):
        self.storage = FakeStorageClient()
        self.tasks = FakeTasksClient()
        self.discovery = FakeDiscovery()
        self.assets = FakeAssets()
        self.recommender = FakeRecommender()
        self.gemini = FakeGemini()
        self.credentials = FakeCredentials()
        self.auth_scopes = []  # the scopes of every google.auth.default() call

    @property
    def bucket(self):
        """The results bucket, ``TEST_ENV['RESULTS_BUCKET']``."""
        return self.storage.bucket(TEST_ENV['RESULTS_BUCKET'])

    def auth_default(self, scopes=None, **kwargs):
        self.auth_scopes.append(scopes)
        return self.credentials, TEST_ENV['PROJECT_ID']

    def install(self, monkeypatch):
        """Patches the library attributes that both implementations read at call time.

        Names bound at import time are not covered: the legacy module's
        ``google_auth_default``, ``google_api_build``, ``vertexai``,
        ``GenerativeModel`` and its two clients, and
        ``app.services.gemini.get_client``. The fixtures in conftest.py re-point those.
        """
        import google.auth
        from google.cloud import asset_v1, recommender_v1, storage, tasks_v2
        from googleapiclient import discovery

        monkeypatch.setattr(google.auth, 'default', self.auth_default)
        monkeypatch.setattr(discovery, 'build', self.discovery)
        monkeypatch.setattr(storage, 'Client', lambda *args, project=None, **kwargs: self.storage.for_project(project))
        monkeypatch.setattr(tasks_v2, 'CloudTasksClient', lambda *args, **kwargs: self.tasks)
        monkeypatch.setattr(asset_v1, 'AssetServiceClient', self.assets.client_class)
        monkeypatch.setattr(recommender_v1, 'RecommenderClient', self.recommender.client_class)
