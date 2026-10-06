#!/usr/bin/env bash
# tools/deploy.sh — deploys CloudGauge, or updates a deployment.
#
# Two Cloud Run services from one image: the web service people open sits behind
# Identity-Aware Proxy (IAP); the worker that runs the scans accepts Cloud Tasks only.
#
#   PROJECT_ID=my-project OPERATORS=group:cloud-team@example.com tools/deploy.sh
#
# Steps (each one is idempotent, so the same command updates a deployment):
#   1. setup    enable the APIs, create the service account with its project roles, create the
#               results bucket, let Cloud Build build (the Compute Engine default service account
#               gets the Cloud Build Service Account role). The organization-level scan roles are a
#               one-time manual step (README › Deployment Instructions › Common Prerequisites).
#   2. build    cloudbuild.yaml builds the image, runs the test suite in it and pushes it only
#               if every test passes.
#   3. worker   deploy WORKER_SERVICE: CLOUDGAUGE_ROLE=worker, --ingress internal, invoked by
#               the service account only (that is what Cloud Tasks uses).
#   4. web      deploy SERVICE: CLOUDGAUGE_ROLE=web, WORKER_URL=<the worker>, --iap; IAP's
#               service agent becomes its invoker.
#   5. access   grant OPERATORS roles/iap.httpsResourceAccessor on SERVICE: that role is what
#               lets a Google account sign in.
#
# Variables (only PROJECT_ID is required):
#   PROJECT_ID        the project CloudGauge runs in
#   REGION            region of the services, the queue and the bucket     [asia-south1]
#   SERVICE           the web service                                       [cloudgauge]
#   WORKER_SERVICE    the worker service                                    [${SERVICE}-worker]
#   QUEUE             Cloud Tasks queue, created by the services at startup [cloudgauge-scan-queue]
#   BUCKET            results bucket                                        [cloudgauge-reports-${PROJECT_ID}]
#   SERVICE_ACCOUNT   service account name or email                         [cloudgauge-sa]
#   IMAGE             image to build or deploy                              [gcr.io/${PROJECT_ID}/${SERVICE}]
#   TAG               image tag                                             [short git hash, else latest]
#   OPERATORS         who may sign in, comma-separated: user:a@x.com, group:g@x.com, domain:x.com
#   EXTRA_ENV         more variables for both services, comma-separated KEY=VALUE pairs
#                     (README › Configuration Reference), e.g. GEMINI_MODEL=gemini-2.5-flash,SCAN_SHARD_SIZE=10
#   SKIP_SETUP=1      skip step 1 (updating a deployment that works)
#   SKIP_BUILD=1      skip step 2 and deploy IMAGE:TAG as it is (a tag an earlier build pushed)
#   PROGRAMMATIC_ACCESS=1
#                     also let the service account through IAP and let your gcloud account sign
#                     tokens for it: tools/iap_token.py then works, for curl and tools/demo_gif.py
#   DRY_RUN=1         print the gcloud commands instead of running them

set -euo pipefail

usage() { sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//'; }

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then usage; exit 0; fi
if [[ -z "${PROJECT_ID:-}" ]]; then usage; echo; echo "PROJECT_ID is required." >&2; exit 2; fi
if ! command -v gcloud >/dev/null 2>&1; then echo "gcloud is not installed: https://cloud.google.com/sdk/install" >&2; exit 2; fi

REGION="${REGION:-asia-south1}"
SERVICE="${SERVICE:-cloudgauge}"
WORKER_SERVICE="${WORKER_SERVICE:-${SERVICE}-worker}"
QUEUE="${QUEUE:-cloudgauge-scan-queue}"
BUCKET="${BUCKET:-cloudgauge-reports-${PROJECT_ID}}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-cloudgauge-sa}"
case "$SERVICE_ACCOUNT" in
  *@*) SA_EMAIL="$SERVICE_ACCOUNT"; SA_NAME="${SERVICE_ACCOUNT%%@*}" ;;
  *)   SA_NAME="$SERVICE_ACCOUNT"; SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" ;;
esac
IMAGE="${IMAGE:-gcr.io/${PROJECT_ID}/${SERVICE}}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${TAG:-$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo latest)}"
OPERATORS="${OPERATORS:-}"
EXTRA_ENV="${EXTRA_ENV:-}"
DRY_RUN="${DRY_RUN:-0}"

# The operators as IAM principals, checked now so that a typo stops the script before it changes anything.
MEMBERS=""
if [[ -n "$OPERATORS" ]]; then
  IFS=',' read -r -a operator_entries <<< "$OPERATORS"
  for member in "${operator_entries[@]+"${operator_entries[@]}"}"; do
    member="$(printf '%s' "$member" | tr -d '[:space:]')"
    [[ -z "$member" ]] && continue
    case "$member" in
      user:*|group:*|domain:*|serviceAccount:*|principal:*|principalSet:*) ;;
      *@*.gserviceaccount.com) member="serviceAccount:${member}" ;;
      *@*) member="user:${member}" ;;
      *) echo "OPERATORS entry '${member}' needs a type: user:, group: or domain:" >&2; exit 2 ;;
    esac
    MEMBERS="${MEMBERS:+${MEMBERS} }${member}"
  done
fi

step() { printf '\n==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
# Every gcloud call goes through here: never interactive, always this project.
g() {
  if [[ "$DRY_RUN" == 1 ]]; then printf '    + gcloud --project %s %s\n' "$PROJECT_ID" "$*" >&2; return 0; fi
  gcloud --quiet --project "$PROJECT_ID" "$@"
}
on_error() {
  echo >&2
  echo "deploy.sh stopped at step: ${CURRENT_STEP:-?}" >&2
  echo "Every step is idempotent: fix the cause and run the same command again. Right after the first setup," >&2
  echo "IAM grants can take a minute to apply; a deploy that failed on a 403 usually succeeds on the next run." >&2
}
trap on_error ERR

step "CloudGauge deployment"
note "project          ${PROJECT_ID} (${REGION})"
note "web service      ${SERVICE}"
note "worker service   ${WORKER_SERVICE}"
note "service account  ${SA_EMAIL}"
note "image            ${IMAGE}:${TAG}"
note "queue / bucket   ${QUEUE} / gs://${BUCKET}"
note "operators        ${MEMBERS:-(none: grant access afterwards, see the end)}"
if [[ "$DRY_RUN" == 1 ]]; then note "DRY RUN: nothing is executed"; fi

# --- project number and URLs ---------------------------------------------------------------------------------------
# Cloud Run's deterministic URLs: known before the services exist, so the worker can be told its
# own URL and nothing has to discover anything at startup.
CURRENT_STEP="project number"
if [[ "$DRY_RUN" == 1 ]]; then
  PROJECT_NUMBER="000000000000"
else
  PROJECT_NUMBER="$(gcloud --project "$PROJECT_ID" projects describe "$PROJECT_ID" --format='value(projectNumber)')"
fi
WORKER_URL="https://${WORKER_SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"
WEB_URL="https://${SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"
IAP_AGENT="service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com"
COMMON_ENV="PROJECT_ID=${PROJECT_ID},LOCATION=${REGION},TASK_QUEUE=${QUEUE},RESULTS_BUCKET=${BUCKET},SERVICE_ACCOUNT_EMAIL=${SA_EMAIL}${EXTRA_ENV:+,${EXTRA_ENV}}"

# --- 1. setup -----------------------------------------------------------------------------------
if [[ "${SKIP_SETUP:-0}" != 1 ]]; then
  CURRENT_STEP="setup"
  step "Enabling the APIs"
  # Two calls: gcloud enables at most 20 APIs per command. What CloudGauge runs on, then what it reads.
  g services enable \
    run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com cloudtasks.googleapis.com \
    iap.googleapis.com iam.googleapis.com iamcredentials.googleapis.com cloudresourcemanager.googleapis.com \
    storage.googleapis.com logging.googleapis.com aiplatform.googleapis.com
  g services enable \
    recommender.googleapis.com securitycenter.googleapis.com servicehealth.googleapis.com \
    advisorynotifications.googleapis.com essentialcontacts.googleapis.com compute.googleapis.com \
    container.googleapis.com sqladmin.googleapis.com osconfig.googleapis.com monitoring.googleapis.com \
    cloudasset.googleapis.com

  step "Service account ${SA_EMAIL}"
  if [[ "$DRY_RUN" == 1 ]] || ! gcloud --project "$PROJECT_ID" iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1; then
    g iam service-accounts create "$SA_NAME" --display-name="CloudGauge Service Account"
  fi
  # Project roles: Gemini calls, and the Cloud Tasks queue the services create and fill.
  for role in roles/aiplatform.user roles/cloudtasks.admin; do
    g projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${SA_EMAIL}" --role="$role" --condition=None >/dev/null
  done
  # On itself: signed CSV links (Token Creator) and Cloud Tasks OIDC tokens (Service Account User).
  for role in roles/iam.serviceAccountTokenCreator roles/iam.serviceAccountUser; do
    g iam service-accounts add-iam-policy-binding "$SA_EMAIL" --member="serviceAccount:${SA_EMAIL}" --role="$role" >/dev/null
  done

  step "Results bucket gs://${BUCKET}"
  if [[ "$DRY_RUN" == 1 ]] || ! gcloud --project "$PROJECT_ID" storage buckets describe "gs://${BUCKET}" >/dev/null 2>&1; then
    # Same region as the services; uniform access is what organization policies usually require.
    g storage buckets create "gs://${BUCKET}" --location="$REGION" --uniform-bucket-level-access
  fi
  g storage buckets add-iam-policy-binding "gs://${BUCKET}" --member="serviceAccount:${SA_EMAIL}" --role=roles/storage.objectAdmin >/dev/null

  step "Letting Cloud Build build"
  # Cloud Build runs as the project's Compute Engine default service account. Organizations commonly
  # withhold its automatic Editor grant, which leaves it unable even to read the uploaded source; the
  # Cloud Build Service Account role is the documented remedy (it also covers pushing the image).
  # On a brand-new project that account appears a few seconds after the Compute API is enabled.
  BUILD_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
  if [[ "$DRY_RUN" != 1 ]]; then
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
      gcloud --project "$PROJECT_ID" iam service-accounts describe "$BUILD_SA" >/dev/null 2>&1 && break
      note "waiting for ${BUILD_SA} to exist..."; sleep 5
    done
  fi
  g projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${BUILD_SA}" --role=roles/cloudbuild.builds.builder --condition=None >/dev/null
fi

# --- 2. build -----------------------------------------------------------------------------------
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  CURRENT_STEP="build"
  step "Building and testing ${IMAGE}:${TAG} with Cloud Build"
  (cd "$REPO_ROOT" && g builds submit . --config cloudbuild.yaml --substitutions="_IMAGE=${IMAGE},_TAG=${TAG}")
fi

# --- 3. worker ----------------------------------------------------------------------------------
CURRENT_STEP="worker"
step "Deploying the worker ${WORKER_SERVICE} (Cloud Tasks only)"
# Long requests, few per instance: a shard can run for 30 minutes. --ingress internal: nothing from
# the internet reaches it, Cloud Tasks does. WORKER_AUDIENCE is a canary-only setting; a full
# deployment clears it.
g run deploy "$WORKER_SERVICE" --region="$REGION" --platform=managed --image="${IMAGE}:${TAG}" \
  --service-account="$SA_EMAIL" --no-allow-unauthenticated --ingress=internal \
  --timeout=3600 --concurrency=4 --memory=2Gi \
  --update-env-vars="${COMMON_ENV},CLOUDGAUGE_ROLE=worker,WORKER_URL=${WORKER_URL}" \
  --remove-env-vars=WORKER_AUDIENCE
# The service account is the identity on every Cloud Tasks request; nobody else may invoke the worker.
g run services add-iam-policy-binding "$WORKER_SERVICE" --region="$REGION" \
  --member="serviceAccount:${SA_EMAIL}" --role=roles/run.invoker --condition=None >/dev/null

# --- 4. web -------------------------------------------------------------------------------------
CURRENT_STEP="web"
step "Deploying the web service ${SERVICE} behind Identity-Aware Proxy"
# Pages and the three on-demand Gemini / Recommender calls: small instances, many requests each.
# --invoker-iam-check undoes a public deployment that disabled the check; --no-allow-unauthenticated
# removes allUsers. PROJECT_NUMBER lets the service verify IAP's signed identity assertions.
g run deploy "$SERVICE" --region="$REGION" --platform=managed --image="${IMAGE}:${TAG}" \
  --service-account="$SA_EMAIL" --no-allow-unauthenticated --iap --invoker-iam-check --ingress=all \
  --timeout=600 --concurrency=80 --memory=1Gi \
  --update-env-vars="${COMMON_ENV},CLOUDGAUGE_ROLE=web,WORKER_URL=${WORKER_URL},PROJECT_NUMBER=${PROJECT_NUMBER}" \
  --remove-env-vars=WORKER_AUDIENCE
# IAP forwards the signed-in person's request as its service agent; gcloud grants this with --iap,
# making it explicit keeps the deployment complete if that step ever fails.
g run services add-iam-policy-binding "$SERVICE" --region="$REGION" \
  --member="serviceAccount:${IAP_AGENT}" --role=roles/run.invoker --condition=None >/dev/null

# --- 5. access ----------------------------------------------------------------------------------
grant_access() {  # $1: a principal; roles/iap.httpsResourceAccessor on the web service is what lets it in
  g iap web add-iam-policy-binding --region="$REGION" --resource-type=cloud-run --service="$SERVICE" \
    --member="$1" --role=roles/iap.httpsResourceAccessor --condition=None >/dev/null
}
if [[ -n "$MEMBERS" ]]; then
  CURRENT_STEP="access"
  step "Granting access to the pages"
  for member in $MEMBERS; do  # unquoted on purpose: a space-separated list
    note "$member"
    grant_access "$member"
  done
fi
if [[ "${PROGRAMMATIC_ACCESS:-0}" == 1 ]]; then
  CURRENT_STEP="programmatic access"
  step "Programmatic access through IAP (tools/iap_token.py)"
  grant_access "serviceAccount:${SA_EMAIL}"
  ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
  case "$ACCOUNT" in
    "") echo "gcloud has no active account (gcloud auth login)." >&2; exit 2 ;;
    *.gserviceaccount.com) ME="serviceAccount:${ACCOUNT}" ;;
    *) ME="user:${ACCOUNT}" ;;
  esac
  g iam service-accounts add-iam-policy-binding "$SA_EMAIL" --member="$ME" --role=roles/iam.serviceAccountTokenCreator >/dev/null
  note "${ME} can now mint tokens:  python tools/iap_token.py ${SA_EMAIL} ${WEB_URL}"
fi

# --- done ---------------------------------------------------------------------------------------
CURRENT_STEP="done"
step "Deployed ${IMAGE}:${TAG}"
note "Open            ${WEB_URL}"
note "Worker          ${WORKER_URL}  (ingress internal: only Cloud Tasks reaches it)"
if [[ -n "$MEMBERS" ]]; then
  note "Who can sign in ${MEMBERS}"
else
  note "Nobody can sign in yet. Grant a person, a group or a domain roles/iap.httpsResourceAccessor:"
  note "  gcloud iap web add-iam-policy-binding --project=${PROJECT_ID} --region=${REGION} --resource-type=cloud-run \\"
  note "    --service=${SERVICE} --member=group:cloud-team@example.com --role=roles/iap.httpsResourceAccessor"
fi
note "IAM changes take up to a minute: a 403 right after a grant goes away on reload."
note "Scans need the organization-level roles of README › Common Prerequisites, granted once to ${SA_EMAIL}."
