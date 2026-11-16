"""
v18.8.1 — API attribution: the client identifier ``app.services.user_agent`` adds to the Google Cloud API calls, the opt-out, and the
way ``app.services.gcp`` and ``app.services.gemini`` hand it to each SDK family (the libraries monkeypatched where the real provider
reads them).
"""
import re
from types import SimpleNamespace

import pytest

from app import config
from app.config import VERSION, Settings
from app.services import gcp, gemini, user_agent
from helpers import make_settings

AGENT = f'cloud-solutions/cloudgauge-v{VERSION}'
TOKEN = re.compile(r'^cloud-solutions/[0-9A-Za-z._\-/]+(\s|$)')


@pytest.fixture
def attribution(monkeypatch):
    """Pins the opt-out for ``user_agent`` and the modules that read it: ``attribution(False)`` turns the identifier off."""
    def set_to(enabled):
        settings = make_settings(CLOUDGAUGE_DISABLE_ATTRIBUTION=None if enabled else 'true')
        monkeypatch.setattr(user_agent, 'get_settings', lambda: settings)
        return settings
    set_to(True)
    return set_to


# --- the identifier and the setting ---

def test_the_identifier_is_the_solution_token_and_the_release():
    assert user_agent.USER_AGENT == AGENT and TOKEN.match(AGENT) and ' ' not in AGENT
    assert user_agent.SAFE_VERSION == VERSION  # the release already fits a product token
    assert re.sub(r'[^0-9A-Za-z._\-/]', '-', '18.8 rc 1') == '18.8-rc-1'  # what the substitution would do to one that did not


@pytest.mark.parametrize('value, enabled', [(None, True), ('', True), ('false', True), ('0', True), ('no', True), ('off', True),
                                            ('true', False), ('TRUE', False), ('True', False), ('1', False), ('yes', False), ('on', False)])
def test_the_opt_out_is_read_like_every_other_switch(value, enabled):
    environ = {} if value is None else {'CLOUDGAUGE_DISABLE_ATTRIBUTION': value}
    assert Settings.from_env(environ).attribution is enabled


def test_an_unreadable_opt_out_value_fails_at_startup():
    with pytest.raises(ValueError, match='CLOUDGAUGE_DISABLE_ATTRIBUTION must be on or off'):
        Settings.from_env({'CLOUDGAUGE_DISABLE_ATTRIBUTION': 'maybe'})


def test_the_helpers_follow_the_setting(attribution):
    info = user_agent.client_info()
    assert info is not None and info.to_user_agent().startswith(AGENT + ' ') and TOKEN.match(info.to_user_agent())
    assert user_agent.genai_http_options() == {'headers': {'user-agent': AGENT}}  # the lower-case key the SDK merges into
    headers = user_agent.request_headers({'Metadata-Flavor': 'Google'})
    assert headers['Metadata-Flavor'] == 'Google' and headers['User-Agent'].startswith(AGENT + ' python-requests/')
    assert user_agent.request_headers({'user-agent': 'mine/1'}) == {'User-Agent': f'{AGENT} mine/1'}  # in front of the caller's, under one key
    attribution(False)
    assert user_agent.client_info() is None and user_agent.genai_http_options() is None
    assert user_agent.request_headers({'Metadata-Flavor': 'Google'}) == {'Metadata-Flavor': 'Google'} and user_agent.authorized_http(object()) is None


def test_the_authorized_transport_sets_the_agent_on_every_request(attribution):
    credentials = SimpleNamespace(token='t', expired=False, valid=True, before_request=lambda request, method, url, headers: headers.update({'authorization': 'Bearer t'}))
    http = user_agent.authorized_http(credentials)
    sent = {}

    def fake_request(uri, method='GET', body=None, headers=None, **kwargs):  # the innermost httplib2 request
        sent.update(headers or {})
        return SimpleNamespace(status=200), b'{}'
    http.http.request = fake_request  # AuthorizedHttp wraps an httplib2.Http as ``http``; set_user_agent wrapped AuthorizedHttp.request
    http.request('https://logging.googleapis.com/v2/x', headers={'user-agent': 'google-api-python-client/2.200.0'})
    assert sent['user-agent'] == f'{AGENT} google-api-python-client/2.200.0' and sent['authorization'] == 'Bearer t'
    assert user_agent.authorized_http(None) is None


def test_the_grpc_transport_factory_puts_the_agent_on_the_channel(attribution):
    """``client_info`` reaches a gRPC call's ``x-goog-api-client`` metadata only; the ``user-agent`` the API records is the channel's, so
    the factory creates the channel with the identifier as its primary user agent — and leaves the client's own endpoint and credentials
    resolution to the client (it is called back with them)."""
    made = {}

    class FakeTransport:
        def __init__(self, channel=None, **kwargs):
            made['init'] = kwargs
            made['channel'] = channel('asset.example:443', credentials='c', options=[('grpc.max_send_message_length', -1)])

        @staticmethod
        def create_channel(host, **kwargs):
            made['created'] = (host, kwargs)
            return 'channel'
    factory = user_agent.grpc_transport(FakeTransport)
    transport = factory(credentials='c', host='asset.example:443', client_info='info', always_use_jwt_access=True)
    assert isinstance(transport, FakeTransport) and made['init'] == {'credentials': 'c', 'host': 'asset.example:443', 'client_info': 'info', 'always_use_jwt_access': True}
    assert made['channel'] == 'channel'
    assert made['created'] == ('asset.example:443', {'credentials': 'c', 'options': [('grpc.max_send_message_length', -1), ('grpc.primary_user_agent', AGENT)]})
    attribution(False)
    assert user_agent.grpc_transport(FakeTransport) is None  # the client's default transport


# --- the real provider ---

@pytest.fixture
def libraries(monkeypatch):
    """Replaces every library the real provider constructs with recorders of ``(args, kwargs)``."""
    calls = {}

    def recorder(name):
        def construct(*args, **kwargs):
            calls.setdefault(name, []).append((args, kwargs))
            return SimpleNamespace(name=name, kwargs=kwargs)
        return construct
    monkeypatch.setattr(gcp.discovery, 'build', recorder('discovery'))
    monkeypatch.setattr(gcp.storage, 'Client', recorder('storage'))
    monkeypatch.setattr(gcp.tasks_v2, 'CloudTasksClient', recorder('tasks'))
    monkeypatch.setattr(gcp.asset_v1, 'AssetServiceClient', recorder('asset'))
    monkeypatch.setattr(gcp.recommender_v1, 'RecommenderClient', recorder('recommender'))
    monkeypatch.setattr(gcp.osconfig_v1, 'OsConfigZonalServiceClient', recorder('osconfig'))
    monkeypatch.setattr(gcp.requests, 'get', recorder('requests'))
    monkeypatch.setattr(user_agent, 'authorized_http', lambda credentials: SimpleNamespace(kind='authorized', credentials=credentials) if credentials is not None and user_agent.attribution_enabled() else None)
    gcp.reset_clients()
    yield calls
    gcp.reset_clients()


def test_the_real_provider_hands_the_identifier_to_every_sdk(attribution, libraries):
    provider = gcp.RealGcp()
    credentials = object()
    provider.api_build('compute', 'v1', credentials=credentials)
    provider.api_build('privilegedaccessmanager', 'v1', credentials=credentials, static_discovery=False)
    provider.api_build('run', 'v1')  # no credentials (the worker-URL lookup's shape): nothing to wrap
    args, kwargs = libraries['discovery'][0]
    assert args == ('compute', 'v1') and 'credentials' not in kwargs and kwargs['http'].kind == 'authorized' and kwargs['http'].credentials is credentials
    assert libraries['discovery'][1][1] == {'http': libraries['discovery'][1][1]['http'], 'static_discovery': False}  # the other arguments pass through
    assert libraries['discovery'][2] == (('run', 'v1'), {})
    assert all(not ('http' in kwargs and 'credentials' in kwargs) for _, kwargs in libraries['discovery'])  # never both
    provider.project_storage_client('p')
    provider.asset_client(credentials=credentials)
    provider.recommender_client(credentials=credentials)
    provider.osconfig_client()
    gcp.storage_client()
    gcp.tasks_client()
    for name in ('storage', 'asset', 'recommender', 'osconfig', 'tasks'):
        for _, kwargs in libraries[name]:
            assert kwargs['client_info'].to_user_agent().startswith(AGENT + ' '), name
    for name in ('asset', 'recommender', 'osconfig', 'tasks'):  # the gRPC clients: a transport factory for the channel's agent
        assert all(callable(kwargs['transport']) for _, kwargs in libraries[name]), name
    assert 'transport' not in libraries['storage'][0][1]
    assert libraries['storage'][0][1]['project'] == 'p' and libraries['asset'][0][1]['credentials'] is credentials
    provider.http_get('https://servicehealth.googleapis.com/v1/projects/p/locations/global/events', params={'filter': 'x'}, timeout=30)
    provider.http_get('https://raw.githubusercontent.com/example/table.csv', timeout=30)
    google_call, github_call = libraries['requests']
    assert google_call[1]['headers']['User-Agent'].startswith(AGENT + ' ') and google_call[1]['params'] == {'filter': 'x'}
    assert 'headers' not in github_call[1]  # not a Google API: left as it was


def test_the_real_provider_falls_back_cleanly_when_attribution_is_off(attribution, libraries):
    attribution(False)
    provider = gcp.RealGcp()
    credentials = object()
    provider.api_build('compute', 'v1', credentials=credentials)
    assert libraries['discovery'] == [(('compute', 'v1'), {'credentials': credentials})]  # credentials as before, no transport, no agent
    provider.project_storage_client('p')
    provider.asset_client(credentials=credentials)
    provider.osconfig_client()
    gcp.storage_client()
    gcp.tasks_client()
    for name in ('storage', 'asset', 'osconfig', 'tasks'):
        assert all(kwargs['client_info'] is None for _, kwargs in libraries[name]), name  # the SDK's default agent
    for name in ('asset', 'osconfig', 'tasks'):
        assert all(kwargs['transport'] is None for _, kwargs in libraries[name]), name  # the client's default transport
    provider.http_get('https://servicehealth.googleapis.com/v1/x', timeout=30)
    assert libraries['requests'] == [(('https://servicehealth.googleapis.com/v1/x',), {'timeout': 30, 'headers': {}})]


def test_the_gemini_client_gets_the_agent_under_the_lower_case_key(attribution, monkeypatch):
    built = []
    monkeypatch.setattr(gemini.genai, 'Client', lambda **kwargs: built.append(kwargs) or SimpleNamespace(**kwargs))
    gemini.get_client.cache_clear()
    gemini.get_client('p', 'global')
    assert built == [{'vertexai': True, 'project': 'p', 'location': 'global', 'http_options': {'headers': {'user-agent': AGENT}}}]
    gemini.get_client.cache_clear()
    attribution(False)
    gemini.get_client('p', 'global')
    assert built[-1]['http_options'] is None
    gemini.get_client.cache_clear()


def test_the_release_in_the_identifier_is_the_one_the_report_names():
    assert config.VERSION in user_agent.USER_AGENT and user_agent.USER_AGENT.endswith(config.VERSION)
