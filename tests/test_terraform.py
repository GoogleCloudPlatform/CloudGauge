"""The Terraform configuration deploys what tools/deploy.sh deploys.

``terraform/`` is a second description of the deployment — the APIs, the roles, the variables both
services get, the limits of the services and the queue, the scheduler job — and a second description
rots unless something ties it to the first. These tests read the files (no Terraform binary needed)
and hold ``terraform/`` to the script, the README's prerequisites and the app's own constants.
"""
import pathlib
import re
import shutil
import subprocess

import pytest

from app import config
from tests import helpers

ROOT = pathlib.Path(__file__).resolve().parent.parent
TERRAFORM = ROOT / 'terraform'
API = re.compile(r'\b([a-z]+\.googleapis\.com)\b')
ROLE = re.compile(r'\broles/[A-Za-z.]+\b')


def without_comments(text):
    """``text`` minus full-line and trailing ``#`` comments (neither file puts a ``#`` inside a string)."""
    return '\n'.join(re.sub(r'(^|\s)#.*$', '', line) for line in text.splitlines())


def joined_lines(text):
    """``text`` with backslash continuations joined, so a multi-line command is one line."""
    return re.sub(r'\\\n\s*', ' ', text)


@pytest.fixture(scope='module')
def tf():
    files = {path.name: path.read_text(encoding='utf-8') for path in sorted(TERRAFORM.glob('*.tf'))}
    assert set(files) == {'main.tf', 'outputs.tf', 'services.tf', 'variables.tf', 'versions.tf'}
    files['all'] = without_comments('\n'.join(files.values()))
    return files


@pytest.fixture(scope='module')
def script():
    return without_comments((ROOT / 'tools' / 'deploy.sh').read_text(encoding='utf-8'))


@pytest.fixture(scope='module')
def readme():
    return (ROOT / 'README.md').read_text(encoding='utf-8')


def hcl_list(text, name):
    """The string items of the HCL list ``name = [...]`` in ``text``."""
    match = re.search(name + r'\s*=\s*\[(.*?)\n\s*\]', text, re.S)
    assert match, f'{name} = [...] not found'
    return re.findall(r'"([^"]+)"', match.group(1))


def hcl_block(text, header):
    """The body of the first block whose header line contains ``header`` (up to the matching closing brace)."""
    start = text.index(header)
    depth, index = 0, text.index('{', start)
    for index in range(index, len(text)):
        depth += {'{': 1, '}': -1}.get(text[index], 0)
        if depth == 0:
            return text[start:index + 1]
    raise AssertionError(f'unbalanced block at {header}')


def enabled_apis(text):
    """Every API named on a ``services enable`` line of ``text`` (continuations joined)."""
    found = set()
    for line in joined_lines(text).splitlines():
        if 'services enable' in line:
            found.update(API.findall(line))
    return found


# --- what is enabled and granted -----------------------------------------------------------------

def test_the_apis_are_the_scripts_and_the_readmes(tf, script, readme):
    terraform = hcl_list(tf['main.tf'], 'apis')
    assert len(terraform) == len(set(terraform)) == 25
    assert set(terraform) == enabled_apis(script), 'terraform/main.tf and tools/deploy.sh enable different APIs'
    assert set(terraform) == enabled_apis(readme), 'terraform/main.tf and README › Common Prerequisites enable different APIs'
    assert 'disable_on_destroy = false' in tf['main.tf']  # other things in the project may use them


def test_the_organization_roles_are_the_readmes(tf, readme):
    """README › Common Prerequisites, step 2 (1): the roles granted on the organization, all read-only."""
    terraform = hcl_list(tf['main.tf'], 'organization_roles')
    documented = re.findall(r'gcloud organizations add-iam-policy-binding \$\{ORG_ID\} .*--role="(roles/[^"]+)"', readme)
    assert len(terraform) == len(set(terraform)) == 12
    assert set(terraform) == set(documented)
    assert all(role.endswith(('Viewer', 'viewer', 'browser', 'securityReviewer', 'settingsViewer')) for role in terraform)


def test_the_advisory_role_is_the_readmes(tf, readme):
    """README › Common Prerequisites, step 2 (1b): the custom role, its ID, title, description and permissions."""
    create = re.search(r'gcloud iam roles create (\w+) --organization=\$\{ORG_ID\} \\\n(.*?)--stage=GA', readme, re.S).group
    assert f'default     = "{create(1)}"' in hcl_block(tf['variables.tf'], 'variable "advisory_role_id"')
    role = hcl_block(tf['main.tf'], 'resource "google_organization_iam_custom_role" "advisory_viewer"')
    assert re.search(r'--title="([^"]+)"', create(2)).group(1) in role
    assert re.search(r'--description="([^"]+)"', create(2)).group(1) in role
    documented = re.search(r'--permissions=(\S+)', create(2)).group(1).split(',')
    assert hcl_list(role, 'permissions') == documented
    assert 'stage = "GA"' in role


def test_the_project_roles_are_the_scripts(tf, script):
    loop = re.search(r'for role in ((?:roles/\S+ ?)+); do', script).group(1).split()
    concat = tf['main.tf'].split('project_roles = concat(')[1].split('\n  )')[0]
    always, with_export = concat.split('local.export ?')
    assert ROLE.findall(always) == loop
    assert ROLE.findall(with_export) == ['roles/bigquery.jobUser']
    assert '--role=roles/bigquery.jobUser' in script


def test_every_role_the_script_grants_is_granted_and_nothing_wider(tf, script, readme):
    """Terraform grants the script's roles plus the README's organization roles — no role from anywhere else."""
    organization = set(re.findall(r'gcloud organizations add-iam-policy-binding \$\{ORG_ID\} .*--role="(roles/[^"]+)"', readme))
    assert set(ROLE.findall(tf['all'])) == set(ROLE.findall(script)) | organization
    assert 'roles/owner' not in tf['all'] and 'roles/editor' not in tf['all']


def test_the_service_account_binds_itself_as_user_only(tf, script):
    """Service Account User on itself (Cloud Tasks carries its token); Token Creator on itself is not needed."""
    self_binding = hcl_block(tf['main.tf'], 'resource "google_service_account_iam_member" "self_user"')
    assert 'roles/iam.serviceAccountUser' in self_binding and 'member             = google_service_account.cloudgauge.member' in self_binding
    assert '--member="serviceAccount:${SA_EMAIL}" --role=roles/iam.serviceAccountUser' in script
    creators = hcl_block(tf['services.tf'], 'resource "google_service_account_iam_member" "token_creators"')
    assert 'for_each = toset(var.programmatic_access_principals)' in creators  # never the account itself


# --- the services ---------------------------------------------------------------------------------

def test_the_services_get_the_required_variables_and_only_known_ones(tf, script):
    names = set(re.findall(r'^\s{6}([A-Z][A-Z_]+)\s+=', hcl_block(tf['main.tf'], 'common_env = merge('), re.M))
    names |= set(re.findall(r'\b([A-Z][A-Z_]+) = ', tf['main.tf'].split('common_env = merge(')[1].split('\n  )')[0]))
    for header in ('"google_cloud_run_v2_service" "worker"', '"google_cloud_run_v2_service" "web"'):
        block = hcl_block(tf['services.tf'], header)
        names |= set(re.findall(r'\{ ([A-Z][A-Z_]+) = ', block)) | set(re.findall(r', ([A-Z][A-Z_]+) = ', block))
    assert set(config.REQUIRED_ENV_VARS) <= names
    assert {'CLOUDGAUGE_ROLE', 'WORKER_URL', 'PROJECT_NUMBER', 'SCAN_MAX_CONCURRENT_SHARDS', 'TASK_MAX_ATTEMPTS'} <= names
    assert names <= set(helpers.APP_ENV_VARS), f'unknown variables: {names - set(helpers.APP_ENV_VARS)}'
    common_env = re.search(r'COMMON_ENV="(.*)"', script).group(1)
    assert set(re.findall(r'\b([A-Z][A-Z_]+)=', common_env)) <= names


def test_the_worker_is_the_scripts(tf, script):
    flags = re.search(r'run deploy "\$WORKER_SERVICE".*?--timeout=(\d+) --concurrency=(\d+) --memory=(\w+)', joined_lines(script), re.S)
    worker = hcl_block(tf['services.tf'], '"google_cloud_run_v2_service" "worker"')
    assert f'timeout                          = "{flags.group(1)}s"' in worker
    assert f'max_instance_request_concurrency = {flags.group(2)}' in worker
    assert f'memory = "{flags.group(3)}"' in worker
    assert '--ingress=internal' in script and 'ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"' in worker
    assert 'CLOUDGAUGE_ROLE = "worker"' in worker and 'iap_enabled' not in worker
    invoker = hcl_block(tf['services.tf'], '"google_cloud_run_v2_service_iam_member" "worker_invoker"')
    assert 'roles/run.invoker' in invoker and 'member   = google_service_account.cloudgauge.member' in invoker


def test_the_web_service_is_the_scripts(tf, script):
    flags = re.search(r'run deploy "\$SERVICE".*?--timeout=(\d+) --concurrency=(\d+) --memory=(\w+)', joined_lines(script), re.S)
    web = hcl_block(tf['services.tf'], '"google_cloud_run_v2_service" "web"')
    assert f'timeout                          = "{flags.group(1)}s"' in web
    assert f'max_instance_request_concurrency = {flags.group(2)}' in web
    assert f'memory = "{flags.group(3)}"' in web
    assert '--iap' in script and 'iap_enabled         = true' in web
    assert '--ingress=all' in script and 'ingress             = "INGRESS_TRAFFIC_ALL"' in web
    assert 'CLOUDGAUGE_ROLE = "web"' in web and 'PROJECT_NUMBER = local.project_number' in web
    assert 'invoker_iam_disabled' not in tf['all']  # never public
    invoker = hcl_block(tf['services.tf'], '"google_cloud_run_v2_service_iam_member" "web_iap_invoker"')
    assert 'roles/run.invoker' in invoker and 'member   = local.iap_agent' in invoker
    assert 'gcp-sa-iap.iam.gserviceaccount.com' in tf['services.tf'] and 'gcp-sa-iap.iam.gserviceaccount.com' in script
    access = hcl_block(tf['services.tf'], '"google_iap_web_cloud_run_service_iam_member" "operators"')
    assert 'roles/iap.httpsResourceAccessor' in access and 'toset(var.operators)' in access


def test_the_worker_url_is_the_deterministic_one(tf, script):
    """Both tell the services the worker's URL up front, so nothing is discovered at startup."""
    assert 'WORKER_URL="https://${WORKER_SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"' in script
    assert 'worker_url = "https://${local.worker_service_name}-${local.project_number}.${var.region}.run.app"' in tf['main.tf']


def test_releases_and_canaries_do_not_fight_terraform(tf):
    """Terraform owns the image and the variables; traffic and tags belong to the operator (README's runbook)."""
    for header in ('"google_cloud_run_v2_service" "worker"', '"google_cloud_run_v2_service" "web"'):
        block = hcl_block(tf['services.tf'], header)
        assert 'ignore_changes = [client, client_version, traffic]' in block
        assert 'image = "${local.image}:${var.image_tag}"' in block
        assert 'deletion_protection = var.deletion_protection' in block


def test_nothing_is_deployed_without_an_image(tf):
    """The first apply creates the foundation; the services wait for image_tag (the output says how to build)."""
    assert 'deploy_services     = var.image_tag != ""' in tf['main.tf']
    for name in ('"google_cloud_run_v2_service" "worker"', '"google_cloud_run_v2_service" "web"', '"google_cloud_run_v2_service_iam_member" "worker_invoker"',
                 '"google_cloud_run_v2_service_iam_member" "web_iap_invoker"', '"google_iap_web_cloud_run_service_iam_member" "programmatic"'):
        assert 'local.deploy_services' in hcl_block(tf['services.tf'], name).split('\n')[1], name
    assert 'for_each = local.deploy_services ? toset(var.operators) : toset([])' in tf['services.tf']
    assert 'for_each = local.deploy_services ? var.schedules : {}' in tf['services.tf']
    assert '--config cloudbuild.yaml' in tf['outputs.tf'] and '--service-account=projects/${var.project_id}/serviceAccounts/' in tf['outputs.tf']


# --- the queue, the export, the schedules ---------------------------------------------------------

def test_the_queue_limits_are_the_apps(tf):
    queue = hcl_block(tf['main.tf'], 'resource "google_cloud_tasks_queue" "scans"')
    assert f'min_backoff  = "{config.QUEUE_MIN_BACKOFF_SECONDS}s"' in queue
    assert f'max_backoff  = "{config.QUEUE_MAX_BACKOFF_SECONDS}s"' in queue
    assert 'max_concurrent_dispatches = var.scan_max_concurrent_shards' in queue and 'max_attempts = var.task_max_attempts' in queue
    assert f'default     = {config.DEFAULT_SCAN_MAX_CONCURRENT_SHARDS}' in hcl_block(tf['variables.tf'], 'variable "scan_max_concurrent_shards"')
    assert f'default     = {config.QUEUE_MAX_ATTEMPTS}' in hcl_block(tf['variables.tf'], 'variable "task_max_attempts"')
    # The services are told the same two numbers, so the queue and the variables cannot disagree.
    assert 'SCAN_MAX_CONCURRENT_SHARDS = tostring(var.scan_max_concurrent_shards)' in tf['main.tf']
    assert 'TASK_MAX_ATTEMPTS          = tostring(var.task_max_attempts)' in tf['main.tf']


def test_the_export_is_the_scripts(tf, script):
    description = re.search(r'--description="([^"]+)"', script).group(1)
    dataset = hcl_block(tf['main.tf'], 'resource "google_bigquery_dataset" "export"')
    assert f'description                = "{description}"' in dataset and 'location                   = var.region' in dataset
    writer = hcl_block(tf['main.tf'], 'resource "google_bigquery_dataset_access" "writer"')
    assert 'role          = "WRITER"' in writer and 'user_by_email = google_service_account.cloudgauge.email' in writer
    assert '"role": "WRITER", "userByEmail": email' in script
    assert 'BIGQUERY_DATASET = var.bigquery_dataset' in tf['main.tf']


def test_the_scheduler_job_is_the_scripts(tf, script):
    job = hcl_block(tf['services.tf'], 'resource "google_cloud_scheduler_job" "schedules"')
    command = re.search(r'scheduler jobs "\$verb" http .*?>/dev/null', joined_lines(script), re.S).group(0)
    assert '--time-zone="Etc/UTC"' in command and 'time_zone        = "Etc/UTC"' in job
    assert '--attempt-deadline=120s' in command and 'attempt_deadline = "120s"' in job
    assert '--max-retry-attempts=0' in command and 'retry_config {' not in without_comments(job)  # no block = no retries, and no diff on every plan
    assert '/scheduled-scan' in command and 'uri         = "${local.worker_url}/scheduled-scan"' in job
    assert '--oidc-token-audience="$WORKER_URL"' in command and 'audience              = local.worker_url' in job
    assert all(f'\\"{key}\\"' in command for key in ('scope', 'scope_id', 'name'))  # the script's JSON body, quotes escaped
    assert 'jsonencode({ scope = each.value.scope, scope_id = each.value.scope_id, name = each.key })' in job
    assert '"organization", "folder", "project"' in hcl_block(tf['variables.tf'], 'variable "schedules"')


# --- the folder itself ----------------------------------------------------------------------------

def test_the_folder_works_as_a_root_and_as_a_module(tf):
    assert 'provider "google"' not in tf['all'], 'a provider block would stop the folder from being used as a module'
    assert re.search(r'required_providers \{\s*google = \{', tf['versions.tf'])
    assert 'google-beta' not in tf['all']
    for header in re.findall(r'^resource "(google_[a-z0-9_]+)" "(\w+)"', tf['all'], re.M):
        block = hcl_block(tf['all'], f'resource "{header[0]}" "{header[1]}"')
        assert re.search(r'\b(project|org_id|bucket|service_account_id|dataset_id)\s*=', block), f'{header} names no project'


def test_every_variable_is_described_and_the_example_names_declared_ones_only(tf):
    declared = re.findall(r'^variable "(\w+)"', tf['variables.tf'], re.M)
    assert len(declared) == len(set(declared))
    for name in declared:
        assert 'description =' in hcl_block(tf['variables.tf'], f'variable "{name}"'), name
    example = (TERRAFORM / 'terraform.tfvars.example').read_text(encoding='utf-8')
    used = re.findall(r'^(?:# )?(\w+)\s*=', example, re.M)
    assert set(used) <= set(declared), set(used) - set(declared)
    assert re.search(r'^project_id\s*=', example, re.M)
    assert {'project_id', 'region', 'operators', 'organization_id', 'bigquery_dataset', 'schedules', 'image_tag'} <= set(used)
    safe = hcl_block(tf['variables.tf'], 'variable "deletion_protection"'), hcl_block(tf['variables.tf'], 'variable "force_destroy"')
    assert 'default     = true' in safe[0] and 'default     = false' in safe[1]


def test_the_folder_is_documented_and_kept_out_of_the_build(readme):
    assert '### **Method 3: Deploy with Terraform**' in readme
    assert '[Method 3: Deploy with Terraform](#method-3-deploy-with-terraform)' in readme
    assert re.search(r'^terraform/\s+#', readme, re.M), 'Project Structure does not list terraform/'
    assert (TERRAFORM / 'README.md').exists() and (TERRAFORM / '.terraform.lock.hcl').exists()
    app_context = (ROOT / '.dockerignore').read_text(encoding='utf-8').splitlines()
    assert 'terraform/' in app_context, 'the application image does not need terraform/'
    for name in ('.gcloudignore', 'Dockerfile.test.dockerignore'):  # the test image reads the folder, so the upload and its context keep it
        lines = (ROOT / name).read_text(encoding='utf-8').splitlines()
        assert 'terraform/' not in lines and {'terraform/.terraform/', 'terraform/terraform.tfvars', '*.tfstate'} <= set(lines), name
    test_context = (ROOT / 'Dockerfile.test.dockerignore').read_text(encoding='utf-8').splitlines()
    assert {'!README.md', '!terraform/README.md'} <= set(test_context)
    dockerfile_test = (ROOT / 'Dockerfile.test').read_text(encoding='utf-8')
    copied = re.search(r'^COPY (.+) \./$', dockerfile_test, re.M).group(1).split()
    assert {'README.md', '.gcloudignore', '.gitignore', 'RELEASE_NOTES.md'} <= set(copied)
    assert 'COPY terraform ./terraform' in dockerfile_test
    ignored = (ROOT / '.gitignore').read_text(encoding='utf-8')
    assert all(entry in ignored for entry in ('.terraform/', '*.tfstate', 'terraform.tfvars'))
    assert 'Terraform' in (ROOT / 'RELEASE_NOTES.md').read_text(encoding='utf-8')


@pytest.mark.skipif(shutil.which('terraform') is None, reason='terraform is not installed')
def test_the_files_are_formatted():
    result = subprocess.run(['terraform', 'fmt', '-check', '-recursive', str(TERRAFORM)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
