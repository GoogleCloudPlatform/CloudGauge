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
"""v20 — the release machinery: tools/release_notes.py and the two GitHub Actions workflows.

A release is a pull request that bumps ``VERSION`` and adds the release's section to ``RELEASE_NOTES.md`` (the
packaging tests hold them together), then a tag; ``release.yml`` publishes the GitHub Release with that section as
its body. These tests keep the tool honest and the workflows pinned and least-privileged — nothing here runs on GitHub.
"""
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / '.github' / 'workflows'
sys.path.insert(0, str(ROOT / 'tools'))
import release_notes  # noqa: E402

SAMPLE = '''# CloudGauge Release Notes

Versions are the image tags (`v5` … `v20.0.0`); the commit is the one that shipped.

## v20.0.0 — The GA release

The modular application replaces the monolith.

### What changed

- Everything.

## v19.3 — Finish what the report points at

Five finishers.

## Roadmap

| Release | Theme |
'''


# --- the tool ---

@pytest.mark.parametrize('given, expected', [
    ('v19.3', '19.3.0'), ('19.3', '19.3.0'), ('v17', '17.0.0'), ('v18.6.1', '18.6.1'),
    ('v20.0.0', '20.0.0'), ('v20.0.0-rc.1', '20.0.0-rc.1'), (' v20.0 \n', '20.0.0'),
])
def test_a_tag_and_a_heading_are_compared_on_three_parts(given, expected):
    assert release_notes.normalised(given) == expected


def test_the_section_runs_to_the_next_heading_and_forgives_the_missing_dot_zeros():
    assert release_notes.section(SAMPLE, 'v20.0.0') == (
        'The GA release', 'The modular application replaces the monolith.\n\n### What changed\n\n- Everything.')
    assert release_notes.section(SAMPLE, 'v19.3.0') == ('Finish what the report points at', 'Five finishers.')  # the tag of a pre-v20 release
    assert release_notes.section(SAMPLE, 'v19.3') == release_notes.section(SAMPLE, 'v19.3.0')
    assert release_notes.section(SAMPLE, 'v20.0.0-rc.1') is None  # a suffix is a different release
    assert release_notes.section(SAMPLE, 'v21.0.0') is None


def test_the_newest_release_note_is_what_the_current_version_would_publish():
    """What `release.yml` would put in the GitHub Release of a tag on today's VERSION: the top section, as a heading and its text."""
    from app.config import VERSION
    notes = (ROOT / 'RELEASE_NOTES.md').read_text(encoding='utf-8')
    title, body = release_notes.section(notes, f'v{VERSION}')
    assert re.search(r'^## v\S+ — .+$', notes, re.M).group(0) == f'## v{VERSION} — {title}'  # the newest section is the release's
    assert body and not re.search(r'^## ', body, re.M) and '### ' in body and len(body) > 500  # one release's narrative, with its subsections


def test_the_command_prints_the_section_or_refuses():
    tool = ROOT / 'tools' / 'release_notes.py'
    from app.config import VERSION
    done = subprocess.run([sys.executable, str(tool), f'v{VERSION}'], capture_output=True, text=True, encoding='utf-8', cwd=ROOT)
    assert done.returncode == 0 and done.stdout.startswith('## ') and done.stderr == ''
    missing = subprocess.run([sys.executable, str(tool), 'v0.0.1'], capture_output=True, text=True, encoding='utf-8', cwd=ROOT)
    assert missing.returncode == 1 and missing.stdout == '' and "no section headed '## v0.0.1 — …'" in missing.stderr
    usage = subprocess.run([sys.executable, str(tool)], capture_output=True, text=True, encoding='utf-8', cwd=ROOT)
    assert usage.returncode == 2 and 'tools/release_notes.py v20.0.0' in usage.stderr


# --- the workflows ---

# The workflows do not ship: the test image (Dockerfile.test) leaves .github/ out, so inside it these tests skip; the
# CI jobs on the checkout run them.
needs_workflows = pytest.mark.skipif(not WORKFLOWS.is_dir(), reason='.github/workflows is not in this checkout (the test image leaves it out)')


def workflow(name):
    return (WORKFLOWS / name).read_text(encoding='utf-8')


@needs_workflows
def test_every_action_is_pinned_to_a_commit_with_its_version_named():
    for path in sorted(WORKFLOWS.glob('*.yml')):
        uses = re.findall(r'^\s*-?\s*uses:\s*(\S+)(.*)$', path.read_text(encoding='utf-8'), re.M)
        assert uses, path.name
        for action, rest in uses:
            assert re.fullmatch(r'[\w.-]+/[\w.-]+(?:/[\w.-]+)*@[0-9a-f]{40}', action), f'{path.name}: {action} is not pinned to a commit'
            assert re.search(r'#\s*v\d+(\.\d+)*', rest), f'{path.name}: {action} does not name its version in a comment'


@needs_workflows
def test_the_workflows_ask_for_the_least_they_need():
    ci, release = workflow('ci.yml'), workflow('release.yml')
    assert re.search(r'^permissions:\n  contents: read\n', ci, re.M)
    assert re.search(r'^permissions:\n  contents: write', release, re.M) and 'pull-requests' not in release
    assert re.search(r"^on:\n  push:\n    tags:\n      - 'v\[0-9\]\*'\n", release, re.M)
    assert 'pull_request' not in release  # a tag publishes; nothing else


@needs_workflows
def test_the_release_workflow_holds_the_tag_to_the_version_and_to_main():
    release = workflow('release.yml')
    assert 'version="$(tr -d \'[:space:]\' < VERSION)"' in release and '"$tag" != "v$version"' in release
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' in release and 'fetch-depth: 0' in release
    assert 'python3 tools/release_notes.py "$tag"' in release
    assert '*-*) prerelease=--prerelease' in release  # v20.0.0-rc.1 is a pre-release
    assert 'gh release create "$GITHUB_REF_NAME" --verify-tag' in release
    for method in ('tools/deploy.sh', '?ref=%s', 'Updating an Existing Deployment'):
        assert method in release  # the body ends with how to deploy the tag


@needs_workflows
def test_ci_runs_the_suite_on_both_interpreters_and_inside_the_image():
    ci = workflow('ci.yml')
    assert "python: ['3.11', '3.13']" in ci
    assert 'python -m pytest -p no:cacheprovider -q --no-header -rfE --ignore=tests/legacy' in ci
    assert 'ruff check --extend-exclude tests/legacy --select E9,F63,F7,F82,F401,F811 app tests tools cloudgauge.py run.py' in ci
    assert 'docker build -f Dockerfile.test --build-arg APP_IMAGE=cloudgauge -t cloudgauge-test .' in ci and 'docker run --rm cloudgauge-test' in ci
    assert 'terraform fmt -check -recursive -diff' in ci and 'terraform init -backend=false -input=false' in ci and 'terraform validate' in ci
    for job in ('name: tests (${{ matrix.python }})', 'name: terraform', 'name: docker'):
        assert job in ci  # the names the ruleset of main requires (.github/rulesets/main.json)
