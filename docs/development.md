# Development

Running the application and the test suite locally, testing the container, continuous integration and cutting a release — and how a deployment customises the Organization Policies table without a rebuild. The repository's layout and how to add a check: [architecture.md › Project Structure](architecture.md#project-structure).

In this page: [Local Development & Testing](#local-development--testing) · [Customising the policy table](#customising-the-policy-table)

## Local Development & Testing

Requires Python 3.11.

```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
```

**Run the app locally.** `run.py` starts the Flask development server with the `development` profile, which skips the Cloud Run startup checks. It listens on `127.0.0.1:8080` by default; `HOST`, `PORT`, and `FLASK_DEBUG` override this.

```
gcloud auth application-default login   # credentials for the Google Cloud APIs
export PROJECT_ID=... LOCATION=... TASK_QUEUE=... RESULTS_BUCKET=... SERVICE_ACCOUNT_EMAIL=...
python run.py
```

Scans are always executed through Cloud Tasks, which must reach a public worker URL. To start scans from a local instance, set `WORKER_URL` to a deployed CloudGauge service.

**Run the tests.** The suite uses in-memory fakes for GCS, Cloud Tasks, and the Google APIs, so it needs no credentials or network access.

```
pytest                         # full suite
pytest tests/test_smoke.py     # quick pre-deploy smoke tests
# Lint: errors, undefined names, and unused/redefined imports
ruff check --select E9,F63,F7,F82,F401,F811 app tests tools cloudgauge.py run.py
```

**Continuous integration.** `.github/workflows/ci.yml` runs the same lint and suite on Python 3.11 (the image) and 3.13, `terraform fmt -check` / `init -backend=false` / `validate` on `terraform/`, and the container build below with the suite inside it, on every pull request and every push to `main`. The four jobs — `tests (3.11)`, `tests (3.13)`, `terraform`, `docker` — are the required status checks of `main`.

**Test the container.** This is what the `test` step in `cloudbuild.yaml` runs:

```
docker build -t cloudgauge .
DOCKER_BUILDKIT=1 docker build -f Dockerfile.test --build-arg APP_IMAGE=cloudgauge -t cloudgauge-test .
docker run --rm cloudgauge-test
```

**Cut a release.** The release number is written in one file, `VERSION` at the repository root (v20): `app/config.py` reads it and the image copies it. A release is one pull request that bumps it, bumps the same number in `terraform/versions.tf`'s `module_name` (a `provider_meta` block takes constants only, so it cannot read the file), and adds the release's `## vX — …` section at the top of `RELEASE_NOTES.md`; `tests/test_packaging.py` and `tests/test_terraform.py` check that the three agree, because the report's footer shows that version and every scan summary records it (it is how a scan tells a check new to the release from one that had nothing to check). Once it is merged, the tag publishes the release: `git fetch origin main && git tag -a v20.0.0 origin/main -m "v20.0.0" && git push origin v20.0.0` — `.github/workflows/release.yml` checks that the tag names that commit's `VERSION` and that the commit is on `main`, takes the release's section of the notes as the body (`tools/release_notes.py`) and creates the GitHub Release, a pre-release when the tag carries a suffix (`v20.0.0-rc.1`). Nothing is built by the release: every deployment method builds the image in the deployer's project from the tagged source. Nothing at runtime reads the release notes — the app image leaves out every `.md` file — and a checkout without them skips that check rather than failing. Pull-request titles are [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `ci:`, `build:`, `chore:`; `feat!:` for a change to the stability surface): the squash commit carries the title, so `git log main` reads as a changelog between two tags.

## Customising the policy table

The **Organization Policies** check scores the scope's effective policies against a table of constraints — `Name`, `Type`, `Recommended to set *`, `ID` — one row per constraint under a category row. Since v18.1 that table has three layers, none of which needs a rebuild:

1. **The bundled table.** `assets/gcp_best_practices.csv` ships inside the image and is the default. A release that changes it says so in the release notes, with the table's digest.
2. **A table of your own.** Set `BEST_PRACTICES_CSV_URL` to a `gs://bucket/object` the service account can read (`roles/storage.objectViewer` on that bucket), or to an `https://` URL fetched anonymously, and the check scores against that file instead. Same columns as the bundled one; copy it as a starting point.
3. **An overrides file.** Upload a CSV with the same columns to `gs://<RESULTS_BUCKET>/config/best_practices_overrides.csv` and it is merged into whichever table is in use, by constraint `ID`, on every scan: a row whose `ID` the table has **replaces** that row in place (change *Must have* to *Should have*, or the expected value); a row with a new `ID` is **added** under the category row it sits beneath; a row with `Skip` in the *Recommended to set* column **removes** the constraint from the evaluation (its other cells may stay empty). Delete the object to go back to the table as it is.

   ```
   Name,Type,Recommended to set *,ID
   Identity,,,
   Disable service account key creation,Boolean,Should have,iam.disableServiceAccountKeyCreation
   Networking,,,
   Restrict VM external IPs,List,Skip,compute.vmExternalIpAccess
   Ours,,,
   Restrict shared VPC host projects,List,Must have,compute.restrictSharedVpcHostProjects
   ```

The report's Organization Policies table carries a **Policy table** line — *bundled table (138 rows, 922e3257c491) · 2 overrides, 1 skipped (gs://…/config/best_practices_overrides.csv)* — so two reports are never compared without knowing what each was scored against. A table that cannot be read, or an overrides file that cannot be read or parsed, is that check's *Error* (the file was put there on purpose; the scan is not scored quietly without it). On the Changes card, the first scan after a `Skip` lists the constraint as *resolved* — it stopped being scored, which the Policy table line records. If a change is good for everyone — a new managed constraint, a recommendation Google changed — send it upstream as a change to `assets/gcp_best_practices.csv`, so the next bundled table carries it and the override can go.
