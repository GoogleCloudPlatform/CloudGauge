"""
Serverless and edge exposure, the serverless half (v18.6).

Cloud Run and Cloud Functions were the one compute family the tool never judged
for exposure or identity. Everything here comes from one Cloud Asset Inventory
read under the scope (services, jobs, functions, serverless NEGs and the
backend services that put them behind a load balancer — the search index first,
the listing as the fallback) plus the public-principal IAM search the data
checks already run, with **fresh reads** per project that has services: the
Cloud Run v2 API (``services.list``, ``getIamPolicy`` per service), the
Cloud Functions v2 API (``functions.list``) and, where serverless NEGs exist,
the Compute API (``networkEndpointGroups`` and ``backendServices``
``aggregatedList``), so a fix shows on the next scan (the v18.5 lesson: the
inventory lags changes by hours; the first v18.6 canary read a backend service
whose NEG, added seconds after its creation, the index still did not show). A refused read leaves
the inventory's copy in place and a line under *Projects not checked*.

- **Serverless Exposure** (Security): a service or function **behind an
  external load balancer** (a serverless NEG in an external backend service)
  whose ingress is still ``all`` — callers reach the ``run.app`` URL and bypass
  the load balancer and its Cloud Armor policy — is Action Required; a
  **public** one (``allUsers`` / ``allAuthenticatedUsers`` on the invoker role,
  *or* the invoker IAM check disabled) with ingress ``all`` and no IAP is
  Investigation. IAP-fronted and internal services are never rows.
- **Serverless Service Accounts** (Security): a service, job or function that
  runs as the Compute Engine or App Engine **default** service account (or
  none, which is the Compute default) — Action Required when the account holds
  a privileged role (``gke_security.PRIVILEGED_ROLES``), Investigation
  otherwise: a Cloud Run token has no scope limit, every role of the account is
  reachable from the container.
- **Container Scanning Enabled** (Security, its own listing): a project with
  standard Docker repositories in Artifact Registry and Artifact Analysis
  (``containerscanning.googleapis.com``) not enabled — no image in it has ever
  been scanned for CVEs.

Second-generation functions are Cloud Run services (that is where their IAM
and ingress live): they are judged once, through the service, labelled as
functions. API Gateway configurations are not read (no API Gateway in the
organization this shipped from; a later addition).

v18.8 adds **Serverless Cost Hygiene** (Cost Optimization, its own listing of
the scope's services, jobs, gen-2 functions and Serverless VPC Access
connectors, then the Cloud Run v2 and VPC Access APIs per project that has
any): a workload whose egress goes through a **connector** (its instances bill
around the clock; Direct VPC egress scales to zero), a connector **no workload
uses**, and a workload whose Cloud SQL instance sits in **another region**
(cross-region egress and latency on every query) — all *Investigation*.
"""
import logging

from google.cloud import asset_v1

from app.checks.data_governance import PUBLIC_MEMBERS, PUBLIC_QUERY, project_ids_by_number, public_policy_rows
from app.checks.edge_security import api_facts
from app.checks.gke_operations import ACTION_REQUIRED, INVESTIGATION, write_rows
from app.checks.gke_security import account_roles, privileged_roles
from app.checks.network_edge import by_kind, is_external, key, list_assets, tail
from app.checks.not_checked import NotChecked
from app.checks.vm_hardening import is_default_account
from app.config import SCOPES
from app.services import gcp

EXPOSURE_CHECK = "Serverless Exposure"
SERVERLESS_SA_CHECK = "Serverless Service Accounts"
SCANNING_CHECK = "Container Scanning Enabled"
COST_CHECK = "Serverless Cost Hygiene"  # v18.8
SERVERLESS_CHECKS = (EXPOSURE_CHECK, SERVERLESS_SA_CHECK)

RUN_SERVICE, RUN_JOB = "run.googleapis.com/Service", "run.googleapis.com/Job"
FUNCTION_GEN1, FUNCTION_GEN2 = "cloudfunctions.googleapis.com/CloudFunction", "cloudfunctions.googleapis.com/Function"
NEG, BACKEND_SERVICES = "compute.googleapis.com/NetworkEndpointGroup", ("compute.googleapis.com/BackendService", "compute.googleapis.com/RegionBackendService")
SERVERLESS_TYPES = [RUN_SERVICE, RUN_JOB, FUNCTION_GEN1, FUNCTION_GEN2, NEG, *BACKEND_SERVICES]
INVOKER_TYPES = [RUN_SERVICE, FUNCTION_GEN1]  # gen-2 functions' IAM lives on their Cloud Run service
REPOSITORY, SERVICE_USAGE = "artifactregistry.googleapis.com/Repository", "serviceusage.googleapis.com/Service"
SCANNING_API = "containerscanning.googleapis.com"
CONNECTOR = "vpcaccess.googleapis.com/Connector"  # v18.8
COST_TYPES = [RUN_SERVICE, RUN_JOB, FUNCTION_GEN2, CONNECTOR]
CONNECTOR_ANNOTATION, INTERFACES_ANNOTATION, SQL_ANNOTATION = "run.googleapis.com/vpc-access-connector", "run.googleapis.com/network-interfaces", "run.googleapis.com/cloudsql-instances"

INVOKER_ROLES = ("roles/run.invoker", "roles/cloudfunctions.invoker")
INGRESS_ALL, INGRESS_INTERNAL, INGRESS_LB = "all", "internal", "internal-and-cloud-load-balancing"
# Every spelling of the three ingress settings: the inventory's annotation, the Cloud Run v2 API, the Cloud Functions API.
INGRESS_NAMES = {"all": INGRESS_ALL, "INGRESS_TRAFFIC_ALL": INGRESS_ALL, "ALLOW_ALL": INGRESS_ALL,
                 "internal": INGRESS_INTERNAL, "INGRESS_TRAFFIC_INTERNAL_ONLY": INGRESS_INTERNAL, "ALLOW_INTERNAL_ONLY": INGRESS_INTERNAL,
                 "internal-and-cloud-load-balancing": INGRESS_LB, "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER": INGRESS_LB, "ALLOW_INTERNAL_AND_GCLB": INGRESS_LB}
FUNCTIONS_LABEL = "goog-managed-by"  # the label Cloud Functions puts on the Cloud Run service of a gen-2 function
SERVICE, JOB, FUNCTION_1, FUNCTION_2 = "service", "job", "function (gen 1)", "function (gen 2)"

EXPOSURE_ALL_CLEAR = ("No Cloud Run service or Cloud Function answers the internet without an identity check, and none behind a load balancer "
                      "can be reached around it.")
SERVERLESS_SA_ALL_CLEAR = "No Cloud Run service, job or Cloud Function runs as the Compute Engine or App Engine default service account."
SCANNING_ALL_CLEAR = "Every project with Docker repositories in Artifact Registry has Artifact Analysis (container scanning) enabled."


# --- facts -----------------------------------------------------------------------------------------------------------

def is_true(value):
    return str(value).strip().lower() == "true"


def ingress_of(value):
    """The ingress setting in the one spelling the rules use (``all`` when unset: the default)."""
    return INGRESS_NAMES.get(str(value or "").strip(), INGRESS_ALL)


def location_of(name):
    parts = str(name or "").split("/")
    return parts[parts.index("locations") + 1] if "locations" in parts and parts.index("locations") + 1 < len(parts) else ""


def project_of(name):
    parts = str(name or "").split("/")
    return parts[parts.index("projects") + 1] if "projects" in parts and parts.index("projects") + 1 < len(parts) else ""


def service_facts(project_id, data, name=""):
    """What the rules read of one Cloud Run service, from the inventory's copy (Knative v1: ``metadata``/``spec``) or the v2 API's
    (``ingress``, ``iapEnabled``, ``invokerIamDisabled``, ``template.serviceAccount``)."""
    metadata, spec = data.get("metadata") or {}, data.get("spec") or {}
    annotations, labels = metadata.get("annotations") or {}, metadata.get("labels") or data.get("labels") or {}
    if "template" in spec:  # the inventory's Knative shape
        ingress, iap, no_iam = annotations.get("run.googleapis.com/ingress"), annotations.get("run.googleapis.com/iap-enabled"), annotations.get("run.googleapis.com/invoker-iam-disabled")
        account = ((spec.get("template") or {}).get("spec") or {}).get("serviceAccountName") or ""
        service_name, number = metadata.get("name") or tail(name), metadata.get("namespace") or ""
    else:  # the v2 API
        ingress, iap, no_iam = data.get("ingress"), data.get("iapEnabled"), data.get("invokerIamDisabled")
        account, service_name, number = (data.get("template") or {}).get("serviceAccount") or "", tail(data.get("name") or name), ""
    location = location_of(name or data.get("name"))
    return {"kind": FUNCTION_2 if labels.get(FUNCTIONS_LABEL) == "cloudfunctions" else SERVICE, "project_id": project_id, "name": service_name, "location": location,
            "resource": f"//run.googleapis.com/projects/{project_id}/locations/{location}/services/{service_name}", "ingress": ingress_of(ingress),
            "iap": is_true(iap), "invoker_iam_disabled": is_true(no_iam), "account": account, "project_number": str(number)}


def job_facts(project_id, data, name=""):
    """A Cloud Run job's identity (the inventory's ``spec.template.spec.template.spec.serviceAccountName`` or the v2 ``template.template.serviceAccount``)."""
    inner = ((((data.get("spec") or {}).get("template") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    account = inner.get("serviceAccountName") or ((data.get("template") or {}).get("template") or {}).get("serviceAccount") or ""
    job_name = (data.get("metadata") or {}).get("name") or tail(data.get("name") or name)
    return {"kind": JOB, "project_id": project_id, "name": job_name, "location": location_of(name or data.get("name")), "resource": name, "ingress": "",
            "iap": False, "invoker_iam_disabled": False, "account": account, "project_number": str((data.get("metadata") or {}).get("namespace") or "")}


def function_facts(project_id, data, name=""):
    """A Cloud Function's facts from the inventory (gen 1 ``CloudFunction``: flat fields; gen 2 ``Function``: ``serviceConfig``) or the v2 API
    (both generations under ``serviceConfig``, ``environment`` telling them apart). Gen 2 functions carry the Cloud Run service that serves them."""
    config = data.get("serviceConfig") or {}
    environment = str(data.get("environment") or "")
    gen2 = environment == "GEN_2" if environment else bool(config)
    account = config.get("serviceAccountEmail") or data.get("serviceAccountEmail") or ""
    function_name = tail(data.get("name") or name)
    location = location_of(name or data.get("name"))
    return {"kind": FUNCTION_2 if gen2 else FUNCTION_1, "project_id": project_id, "name": function_name, "location": location,
            "resource": f"//cloudfunctions.googleapis.com/projects/{project_id}/locations/{location}/functions/{function_name}",
            "ingress": ingress_of(config.get("ingressSettings") or data.get("ingressSettings")), "iap": False, "invoker_iam_disabled": False, "account": account,
            "http": bool(data.get("httpsTrigger")) or (not data.get("eventTrigger") and bool(config.get("uri") or data.get("url") or data.get("httpsTrigger"))),
            "service": str(config.get("service") or ""), "project_number": ""}


def workloads_from_inventory(grouped):
    """``{resource: fact}`` of the services, jobs and gen-1 functions under the scope; gen-2 functions only name their service."""
    found, gen2_services = {}, {}
    for fact in grouped.get("functions", []):
        function = function_facts(fact["project_id"], fact["data"], fact["link"])
        if function["kind"] == FUNCTION_2:
            if function["service"]:
                gen2_services[key(function["service"])] = function["name"]
            continue
        found[function["resource"]] = function
    for fact in grouped.get("services", []):
        service = service_facts(fact["project_id"], fact["data"], fact["link"])
        if key(f"projects/{service['project_id']}/locations/{service['location']}/services/{service['name']}") in gen2_services:
            service["kind"] = FUNCTION_2
        found[service["resource"]] = service
    for fact in grouped.get("jobs", []):
        job = job_facts(fact["project_id"], fact["data"], fact["link"])
        found[job["resource"] or f"//run.googleapis.com/projects/{job['project_id']}/locations/{job['location']}/jobs/{job['name']}"] = job
    return found


def behind_load_balancers(grouped):
    """``{service or function resource: backend service name}`` for the serverless NEGs that an **external** backend service uses: the
    workloads a load balancer (and whatever Cloud Armor policy it carries) stands in front of."""
    negs = {}
    for neg in grouped.get("networkEndpointGroups", []):
        data = neg["data"]
        if str(data.get("networkEndpointType") or "").upper() != "SERVERLESS":
            continue
        run, function = data.get("cloudRun") or {}, data.get("cloudFunction") or {}
        if run.get("service"):
            target = f"//run.googleapis.com/projects/{neg['project_id']}/locations/{neg['region']}/services/{run['service']}"
        elif function.get("function"):
            target = f"//cloudfunctions.googleapis.com/projects/{neg['project_id']}/locations/{neg['region']}/functions/{function['function']}"
        else:
            continue  # a URL-mask NEG names no single workload
        negs[key(neg["link"])] = target
    fronted = {}
    for service in grouped.get("backendServices", []):
        if not is_external(service["data"]):
            continue
        for backend in service["data"].get("backends") or []:
            target = negs.get(key(backend.get("group")))
            if target:
                fronted.setdefault(target, service["name"])
    return fronted


def public_invokers(public_policies):
    """``{resource: member}`` — the public principal on an invoker role per service or gen-1 function, from the IAM search (or a policy)."""
    found = {}
    for resource, grants in public_policies.items():
        for role, member in grants:
            if role in INVOKER_ROLES:
                found.setdefault(resource, member)
    return found


# --- Serverless Exposure -----------------------------------------------------------------------------------------------

def exposure_rows(workloads, fronted, invokers):
    rows = []
    for resource, w in sorted(workloads.items(), key=lambda item: (item[1]["project_id"], item[1]["kind"], item[1]["name"])):
        if w["kind"] == JOB or (w["kind"] == FUNCTION_1 and not w.get("http", True)) or w["ingress"] != INGRESS_ALL:
            continue
        member = invokers.get(resource)
        public = bool(member) or w["invoker_iam_disabled"]
        how = "the invoker IAM check is disabled" if w["invoker_iam_disabled"] else (f"{member} holds the invoker role" if member else "callers need the invoker role")
        is_function = w["kind"] == FUNCTION_1
        host = "cloudfunctions.net" if is_function else "run.app"
        base = f"gcloud functions deploy {w['name']} --region={w['location']} --project={w['project_id']}" if is_function else f"gcloud run services update {w['name']} --region={w['location']} --project={w['project_id']}"
        row = {"Project": w["project_id"], "Workload": w["name"], "Location": w["location"], "Kind": w["kind"], "Ingress": w["ingress"], "Invoker": "public" if public else "IAM"}
        if resource in fronted:
            iap_note = "; IAP on the service still authenticates callers, the WAF is what is skipped" if w["iap"] else ""
            rows.append({**row, "Issue": "Load balancer bypassed.",
                         "Detail": f"Behind backend service {fronted[resource]} but ingress is all: the {host} URL answers directly, around the load balancer and any Cloud Armor "
                                   f"policy on it ({how}{iap_note}).",
                         "Fix": f"{base} --ingress-settings=internal-and-gclb" if is_function else f"{base} --ingress=internal-and-cloud-load-balancing",
                         "_status": INVESTIGATION if w["iap"] else ACTION_REQUIRED})
        elif public and not w["iap"]:
            if is_function:
                fix = f"gcloud functions remove-invoker-policy-binding {w['name']} --region={w['location']} --project={w['project_id']} --member={member}  # then grant the invoker role to the callers"
            elif w["invoker_iam_disabled"]:
                fix = f"{base} --invoker-iam-check  # then grant roles/run.invoker to the callers, or front it with IAP: {base} --iap"
            else:
                fix = f"gcloud run services remove-iam-policy-binding {w['name']} --region={w['location']} --project={w['project_id']} --member={member} --role=roles/run.invoker  # or front it with IAP: {base} --iap"
            rows.append({**row, "Issue": "Public endpoint.",
                         "Detail": f"Anyone on the internet reaches the {host} URL ({how}; ingress all; IAP off). Legitimate for a public site — otherwise put IAP or an "
                                   "authenticated caller in front.", "Fix": fix, "_status": INVESTIGATION})
    return rows


# --- Serverless Service Accounts ---------------------------------------------------------------------------------------

def default_accounts_in_use(workloads):
    """The distinct default accounts the workloads run as, in first-seen order (an unset account is the project's Compute default)."""
    seen = []
    for w in workloads.values():
        email = effective_account(w)
        if is_default_account(email) and email not in seen:
            seen.append(email)
    return seen


def effective_account(w):
    """The account a workload runs as: its own, or the project's Compute Engine default when none is set (and the number is known)."""
    if w["account"]:
        return w["account"]
    return f"{w['project_number']}-compute@developer.gserviceaccount.com" if w.get("project_number") else ""


def service_account_rows(workloads, roles_by_account):
    rows = []
    for _, w in sorted(workloads.items(), key=lambda item: (item[1]["project_id"], item[1]["kind"], item[1]["name"])):
        email = effective_account(w)
        if not (is_default_account(email) or (not w["account"] and not email)):
            continue
        roles = roles_by_account.get(email) if email else None
        privileged = privileged_roles(roles)
        shown = email or "(not set: the Compute Engine default)"
        which = "App Engine" if email.endswith("@appspot.gserviceaccount.com") else "Compute Engine"
        if privileged:
            detail = f"Runs as the {which} default service account, which holds {', '.join(privileged)} on the project — every role is reachable from the container (a Cloud Run token has no scope limit)."
        elif roles is None:
            detail = f"Runs as the {which} default service account; its roles could not be read — every role it holds is reachable from the container."
        else:
            detail = f"Runs as the {which} default service account (no privileged role today); every role it is ever given becomes reachable from the container."
        dedicated = (f"run-{w['name']}" if w["kind"] in (SERVICE, FUNCTION_2) else ("job-" if w["kind"] == JOB else "fn-") + w["name"])[:30].rstrip("-")
        create = f"gcloud iam service-accounts create {dedicated} --project={w['project_id']}"
        account_flag = f"--service-account={dedicated}@{w['project_id']}.iam.gserviceaccount.com"
        if w["kind"] == JOB:
            update = f"gcloud run jobs update {w['name']} --region={w['location']} --project={w['project_id']} {account_flag}"
        elif w["kind"] == FUNCTION_1:
            update = f"gcloud functions deploy {w['name']} --region={w['location']} --project={w['project_id']} {account_flag}"
        else:
            update = f"gcloud run services update {w['name']} --region={w['location']} --project={w['project_id']} {account_flag}"
        rows.append({"Project": w["project_id"], "Workload": w["name"], "Location": w["location"], "Kind": w["kind"], "Service Account": shown,
                     "Issue": "Default service account.", "Detail": detail, "Fix": f"{create} && {update}  # grant it the roles the workload needs first",
                     "_status": ACTION_REQUIRED if privileged else INVESTIGATION})
    return rows


# --- fresh reads ----------------------------------------------------------------------------------------------------------

def api_services(run, project_id):
    """Every Cloud Run service of ``project_id`` from the v2 API (all locations, paged), as facts keyed by resource."""
    found, collection = {}, run.projects().locations().services()
    request = collection.list(parent=f"projects/{project_id}/locations/-")
    while request:
        response = request.execute()
        for data in response.get("services") or []:
            fact = service_facts(project_id, data, data.get("name"))
            found[fact["resource"]] = fact
        request = collection.list_next(previous_request=request, previous_response=response)
    return found


def api_jobs(run, project_id, locations):
    """The project's Cloud Run jobs from the v2 API, per location (the API refuses the ``-`` wildcard for jobs)."""
    found, collection = {}, run.projects().locations().jobs()
    for location in sorted(locations):
        request = collection.list(parent=f"projects/{project_id}/locations/{location}")
        while request:
            response = request.execute()
            for data in response.get("jobs") or []:
                fact = job_facts(project_id, data, data.get("name"))
                found[f"//run.googleapis.com/{data.get('name')}"] = fact
            request = collection.list_next(previous_request=request, previous_response=response)
    return found


def api_functions(functions, project_id):
    """The project's Cloud Functions, both generations, from the v2 API (gen 2 ones only name their service)."""
    found, gen2_services, collection = {}, {}, functions.projects().locations().functions()
    request = collection.list(parent=f"projects/{project_id}/locations/-")
    while request:
        response = request.execute()
        for data in response.get("functions") or []:
            fact = function_facts(project_id, data, data.get("name"))
            if fact["kind"] == FUNCTION_2:
                if fact["service"]:
                    gen2_services[key(fact["service"])] = fact["name"]
                continue
            found[fact["resource"]] = fact
        request = collection.list_next(previous_request=request, previous_response=response)
    return found, gen2_services


def api_public_invoker(run, resource):
    """The public principal on ``roles/run.invoker`` of one service, from ``getIamPolicy`` (``None`` for none)."""
    policy = run.projects().locations().services().getIamPolicy(resource=resource.split("//run.googleapis.com/", 1)[-1]).execute()
    for binding in policy.get("bindings") or []:
        if binding.get("role") in INVOKER_ROLES:
            for member in binding.get("members") or []:
                if member in PUBLIC_MEMBERS:
                    return member
    return None


def refresh_load_balancers(grouped, compute, skipped):
    """The backend services of every project that has a serverless NEG, re-read from the Compute API (global and regional in one
    ``aggregatedList``): the index keeps a backend service's creation snapshot (an empty ``backends`` list) for hours after a NEG is added
    to it — the first canary of v18.6 read exactly that. The NEGs stay the inventory's: a NEG's target is immutable and the index shows a
    new one within minutes (and ``networkEndpointGroups.aggregatedList`` returns zonal groups only). The inventory's copy stands when a
    read is refused (noted under *Projects not checked*)."""
    projects = sorted({neg["project_id"] for neg in grouped.get("networkEndpointGroups", []) if str(neg["data"].get("networkEndpointType") or "").upper() == "SERVERLESS"})
    for project_id in projects:
        try:
            backends = api_facts(compute, project_id, "backendServices", "backendServices", "backendServices")
        except Exception as e:
            skipped.add(project_id, e, detail="load balancers: the Compute API read failed; the inventory's copy was used, which can lag changes by hours")
            continue
        grouped["backendServices"] = [f for f in grouped.get("backendServices", []) if f["project_id"] != project_id] + backends
    return grouped


def refresh_from_api(workloads, invokers, credentials, skipped):
    """The services, jobs and functions of every project that has any, re-read from the Cloud Run and Cloud Functions APIs, and the
    invoker policy of every service: the inventory told which projects (and job locations) to ask and stands in when a read is refused
    (noted under *Projects not checked*). Returns ``(workloads, invokers)``."""
    by_project = {}
    for resource, w in workloads.items():
        by_project.setdefault(w["project_id"], []).append(w)
    run = functions_api = None
    for project_id in sorted(by_project):
        kinds = {w["kind"] for w in by_project[project_id]}
        if kinds & {SERVICE, FUNCTION_2, JOB}:
            run = run or gcp.api_build("run", "v2", credentials=credentials)
            try:
                fresh = api_services(run, project_id)
                fresh.update(api_jobs(run, project_id, {w["location"] for w in by_project[project_id] if w["kind"] == JOB}))
                gen2 = {(w["location"], w["name"]) for w in by_project[project_id] if w["kind"] == FUNCTION_2}
                for fact in fresh.values():  # the inventory's gen-2 labelling survives the refresh
                    if (fact["location"], fact["name"]) in gen2:
                        fact["kind"] = FUNCTION_2
                workloads = {r: w for r, w in workloads.items() if not (w["project_id"] == project_id and w["kind"] in (SERVICE, FUNCTION_2, JOB))}
                workloads.update(fresh)
            except Exception as e:
                skipped.add(project_id, e, detail="Cloud Run services and jobs: the API read failed; the inventory's copy was used, which can lag changes by hours")
                fresh = {}
            for resource, fact in fresh.items():
                if fact["kind"] == JOB:
                    continue
                try:
                    member = api_public_invoker(run, resource)
                    invokers.pop(resource, None)
                    if member:
                        invokers[resource] = member
                except Exception as e:
                    skipped.add(project_id, e, detail=f"invoker policy of {fact['name']}: the API read failed; the IAM search's copy was used")
        if FUNCTION_1 in kinds:
            functions_api = functions_api or gcp.api_build("cloudfunctions", "v2", credentials=credentials)
            try:
                fresh, _ = api_functions(functions_api, project_id)
                workloads = {r: w for r, w in workloads.items() if not (w["project_id"] == project_id and w["kind"] == FUNCTION_1)}
                workloads.update(fresh)
            except Exception as e:
                skipped.add(project_id, e, detail="Cloud Functions: the API read failed; the inventory's copy was used, which can lag changes by hours")
    return workloads, invokers


# --- the checks -------------------------------------------------------------------------------------------------------------

def check_serverless_posture(scope, scope_id, job_id, *, sink):
    """Writes *Serverless Exposure* and *Serverless Service Accounts*: the scope's serverless workloads and their load balancers from the
    inventory, the public invokers from the IAM search, then each project's workloads and invoker policies from the APIs."""
    print(f"☁️ [{job_id}] Checking {EXPOSURE_CHECK} and {SERVERLESS_SA_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        grouped = by_kind(list_assets(asset_client, parent, SERVERLESS_TYPES))
    except Exception as e:
        logging.error(f"[{job_id}] {EXPOSURE_CHECK}: could not list under {parent}: {e}")
        for check in SERVERLESS_CHECKS:
            sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped, sa_skipped, invokers, roles_by_account = NotChecked(EXPOSURE_CHECK), NotChecked(SERVERLESS_SA_CHECK), {}, {}
    if grouped.get("networkEndpointGroups"):
        grouped = refresh_load_balancers(grouped, gcp.api_build("compute", "v1", credentials=credentials), skipped)
    workloads, fronted = workloads_from_inventory(grouped), behind_load_balancers(grouped)
    try:
        invokers = public_invokers(public_policy_rows(asset_client.search_all_iam_policies(request={"scope": parent, "query": PUBLIC_QUERY, "asset_types": INVOKER_TYPES})))
    except Exception as e:
        skipped.add(parent, e, detail="public invokers: the IAM policy search failed; only the invoker-check setting and the API policies were read")
    workloads, invokers = refresh_from_api(workloads, invokers, credentials, skipped)
    for email in default_accounts_in_use(workloads):
        try:
            roles_by_account[email] = account_roles(asset_client, parent, email)
        except Exception as e:
            roles_by_account[email] = None
            sa_skipped.add(parent, e, detail=f"roles of {email}: the IAM search failed")
    write_rows(sink, job_id, EXPOSURE_CHECK, exposure_rows(workloads, fronted, invokers), EXPOSURE_ALL_CLEAR)
    write_rows(sink, job_id, SERVERLESS_SA_CHECK, service_account_rows(workloads, roles_by_account), SERVERLESS_SA_ALL_CLEAR)
    skipped.write(sink, job_id)
    sa_skipped.write(sink, job_id)


def repository_facts(result):
    """``(project_id, project_number, name, format, mode)`` from a search result (``versioned_resources``, ``project``) or a listed asset
    (``resource.data``, ``resource.parent``) of a repository."""
    name = str(getattr(result, "name", "") or "")
    versions = list(getattr(result, "versioned_resources", None) or [])
    if versions:
        version = versions[0]
        data = (version.get("resource") if isinstance(version, dict) else asset_v1.VersionedResource.to_dict(version).get("resource")) or {}
    else:
        data = getattr(getattr(result, "resource", None), "data", None) or {}
    number = str(getattr(result, "project", "") or getattr(getattr(result, "resource", None), "parent", "") or "").split("/")[-1]
    return project_of(name), number, name.split("/repositories/")[-1], str(data.get("format") or ""), str(data.get("mode") or "STANDARD_REPOSITORY")


def scanning_rows(repositories, scanning_numbers):
    """One row per project with standard Docker repositories and no Artifact Analysis: ``repositories`` as :func:`repository_facts` tuples,
    ``scanning_numbers`` the numbers of the projects where ``containerscanning.googleapis.com`` is enabled."""
    by_project = {}
    for project_id, number, name, fmt, mode in repositories:
        if fmt.upper() == "DOCKER" and mode.upper() in ("STANDARD_REPOSITORY", ""):
            by_project.setdefault((project_id, number), []).append(name)
    rows = []
    for (project_id, number), names in sorted(by_project.items()):
        if number in scanning_numbers:
            continue
        rows.append({"Project": project_id, "Repositories": f"{len(names)} Docker: " + ", ".join(sorted(names)[:5]) + (" …" if len(names) > 5 else ""),
                     "Issue": "Container scanning off.", "Detail": "Artifact Analysis is not enabled: no image pushed to these repositories has been scanned for known CVEs, "
                                                                   "and nothing will be until it is (billed per image scanned).",
                     "Fix": f"gcloud services enable {SCANNING_API} --project={project_id}", "_status": INVESTIGATION})
    return rows


def refresh_scanning(repositories, scanning, serviceusage, skipped):
    """Artifact Analysis's state in every project with Docker repositories, from the Service Usage API (``services.get``, one call per
    project): the index shows a newly enabled service minutes later — the v18.6 closed loop read the row once more right after the fix.
    The search's answer stands for a project whose read is refused (noted under *Projects not checked*)."""
    projects = sorted({(project_id, number) for project_id, number, _, fmt, mode in repositories if fmt.upper() == "DOCKER" and mode.upper() in ("STANDARD_REPOSITORY", "")})
    for project_id, number in projects:
        try:
            service = serviceusage.services().get(name=f"projects/{project_id}/services/{SCANNING_API}").execute()
        except Exception as e:
            skipped.add(project_id, e, detail="Artifact Analysis: the Service Usage read failed; the inventory's answer was used, which can lag an enablement by minutes")
            continue
        number = project_of(service.get("name")) or number
        if str(service.get("state") or "").upper() == "ENABLED":
            scanning.add(number)
        else:
            scanning.discard(number)
    return scanning


def check_container_scanning(scope, scope_id, job_id, *, sink):
    """Writes *Container Scanning Enabled*: the scope's Artifact Registry repositories and the projects where Artifact Analysis is on,
    both from the search index (an enabled service is an asset; a disabled one is absent), then each such project's service state from
    the Service Usage API."""
    print(f"🔬 [{job_id}] Checking {SCANNING_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        try:
            repositories = [repository_facts(r) for r in asset_client.search_all_resources(request={"scope": parent, "asset_types": [REPOSITORY], "read_mask": "*", "page_size": 500})]
        except Exception as e:
            logging.warning(f"[{job_id}] {SCANNING_CHECK}: repository search under {parent} failed ({e}); reading the listing")
            repositories = [repository_facts(r) for r in list_assets(asset_client, parent, [REPOSITORY])]
        scanning = set()
        if repositories:
            for result in asset_client.search_all_resources(request={"scope": parent, "asset_types": [SERVICE_USAGE], "query": f"name:{SCANNING_API}", "page_size": 500}):
                if str(getattr(result, "name", "")).endswith("/services/" + SCANNING_API) and str(getattr(result, "state", "") or "ENABLED").upper() == "ENABLED":
                    scanning.add(str(getattr(result, "project", "") or "").split("/")[-1] or project_of(getattr(result, "name", "")))
    except Exception as e:
        logging.error(f"[{job_id}] {SCANNING_CHECK}: could not read under {parent}: {e}")
        sink.write_finding(job_id, SCANNING_CHECK.replace(" ", "_"), {"Check": SCANNING_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped = NotChecked(SCANNING_CHECK)
    if repositories:
        scanning = refresh_scanning(repositories, scanning, gcp.api_build("serviceusage", "v1", credentials=credentials), skipped)
    write_rows(sink, job_id, SCANNING_CHECK, scanning_rows(repositories, scanning), SCANNING_ALL_CLEAR)
    skipped.write(sink, job_id)


# --- v18.8: Serverless Cost Hygiene -----------------------------------------------------------------------------------------

COST_ALL_CLEAR = "No Cloud Run workload pays for an always-on VPC connector or crosses regions to its database, and no connector sits unused."


def annotations_in(data):
    """Every ``annotations`` mapping in a Knative resource (the service's, the revision template's, a job's task template's), merged."""
    merged = {}

    def walk(node):
        if isinstance(node, dict):
            annotations = node.get("annotations")
            if isinstance(annotations, dict):
                merged.update(annotations)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(data)
    return merged


def connector_key(project_id, location, value):
    """``projects/p/locations/r/connectors/c`` of a connector reference: a full name, or the short name of a connector in the workload's project and region."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "/connectors/" in text:
        return text.split("//vpcaccess.googleapis.com/", 1)[-1]
    return f"projects/{project_id}/locations/{location}/connectors/{text}"


def sql_region(instance):
    """The region of a ``project:region:instance`` connection name (``""`` when the name has no region)."""
    parts = str(instance or "").split(":")
    return parts[1] if len(parts) == 3 else ""


def cost_facts(project_id, data, name="", kind=SERVICE):
    """What the cost rules read of one workload — the inventory's Knative copy, the v2 API's shape, or a gen-2 function's ``serviceConfig``:
    ``{kind, project_id, name, location, connector, direct_vpc, sql_instances}``."""
    location = location_of(name or data.get("name"))
    annotations = annotations_in(data)
    connector, direct, instances = annotations.get(CONNECTOR_ANNOTATION) or "", bool(annotations.get(INTERFACES_ANNOTATION)), []
    instances += [i.strip() for i in str(annotations.get(SQL_ANNOTATION) or "").split(",") if i.strip()]
    template = data.get("template") or {}
    for shape in (template, template.get("template") or {}):  # a v2 service's template; a v2 job's execution template's task template
        access = shape.get("vpcAccess") or {}
        connector = connector or access.get("connector") or ""
        direct = direct or bool(access.get("networkInterfaces"))
        for volume in shape.get("volumes") or []:
            instances += list((volume.get("cloudSqlInstance") or {}).get("instances") or [])
    config = data.get("serviceConfig") or {}  # a gen-2 function from the inventory
    connector = connector or config.get("vpcConnector") or ""
    if config.get("service"):
        workload_name = tail(config["service"])
    else:
        workload_name = (data.get("metadata") or {}).get("name") or tail(data.get("name") or name)
    return {"kind": kind, "project_id": project_id, "name": workload_name, "location": location,
            "connector": connector_key(project_id, location, connector), "direct_vpc": direct, "sql_instances": list(dict.fromkeys(instances))}


def cost_workloads(grouped):
    """``{(project, kind, name): fact}`` of the scope's services, jobs and gen-2 functions (a function's service carries its settings; the function
    adds its connector when the service listing lacks it)."""
    found = {}
    for fact in grouped.get("services", []):
        w = cost_facts(fact["project_id"], fact["data"], fact["link"], FUNCTION_2 if ((fact["data"].get("metadata") or {}).get("labels") or {}).get(FUNCTIONS_LABEL) == "cloudfunctions" else SERVICE)
        found[(w["project_id"], w["location"], w["name"])] = w
    for fact in grouped.get("jobs", []):
        w = cost_facts(fact["project_id"], fact["data"], fact["link"], JOB)
        found[(w["project_id"], w["location"], "job:" + w["name"])] = w
    for fact in grouped.get("functions", []):
        w = cost_facts(fact["project_id"], fact["data"], fact["link"], FUNCTION_2)
        key_ = (w["project_id"], w["location"], w["name"])
        if key_ in found:
            found[key_]["kind"] = FUNCTION_2
            found[key_]["connector"] = found[key_]["connector"] or w["connector"]
        elif w["connector"] or w["sql_instances"]:
            found[key_] = w
    return found


def connector_facts(fact):
    """``{key, project_id, name, region, network, subnet, min_instances, max_instances, machine_type}`` of a connector asset's fact."""
    data = fact["data"]
    full = str(data.get("name") or fact["link"] or "").split("//vpcaccess.googleapis.com/", 1)[-1]
    subnet = (data.get("subnet") or {}).get("name") or ""
    return {"key": full, "project_id": fact["project_id"], "name": tail(full), "region": location_of(full) or fact["region"],
            "network": tail(data.get("network")) if data.get("network") else "", "subnet": subnet,
            "min_instances": int(data.get("minInstances") or 2), "max_instances": int(data.get("maxInstances") or 10), "machine_type": data.get("machineType") or "e2-micro"}


def serverless_cost_rows(workloads, connectors):
    """The rows: a workload on a connector, an idle connector, a workload whose Cloud SQL instance is in another region."""
    rows, used = [], set()
    by_key = {c["key"]: c for c in connectors}
    for w in sorted(workloads.values(), key=lambda w: (w["project_id"], w["kind"], w["name"])):
        update = f"gcloud run jobs update {w['name']}" if w["kind"] == JOB else f"gcloud run services update {w['name']}"
        base = f"{update} --region={w['location']} --project={w['project_id']}"
        row = {"Project": w["project_id"], "Workload": w["name"], "Location": w["location"], "Kind": w["kind"]}
        if w["connector"]:
            used.add(w["connector"])
            connector = by_key.get(w["connector"])
            if connector:
                where = (f"connector {connector['name']} in {connector['region']} keeps {connector['min_instances']}–{connector['max_instances']} {connector['machine_type']} "
                         f"instances billed around the clock")
                network, subnet = connector["network"] or "<network>", connector["subnet"] or "<subnet with free addresses>"
            else:
                where, network, subnet = f"connector {tail(w['connector'])} (its instances are billed around the clock)", "<network>", "<subnet with free addresses>"
            rows.append({**row, "Issue": "Serverless VPC Access connector.",
                         "Detail": f"Egress goes through {where}; Direct VPC egress sends it from the subnet itself and scales to zero with the workload.",
                         "Fix": f"{base} --network={network} --subnet={subnet} --clear-vpc-connector  # the subnet needs free addresses for the instances", "_status": INVESTIGATION})
        for instance in w["sql_instances"]:
            region = sql_region(instance)
            if region and w["location"] and region != w["location"]:
                rows.append({**row, "Issue": "Cloud SQL in another region.",
                             "Detail": f"Connects to {instance} in {region} from {w['location']}: every query crosses regions (egress billed, latency on each round trip).",
                             "Fix": f"gcloud run deploy {w['name']} --region={region} --project={w['project_id']} --image=<the image>  # redeploy beside the instance, or add a read replica in {w['location']}",
                             "_status": INVESTIGATION})
    for connector in sorted(connectors, key=lambda c: (c["project_id"], c["region"], c["name"])):
        if connector["key"] in used:
            continue
        rows.append({"Project": connector["project_id"], "Workload": connector["name"], "Location": connector["region"], "Kind": "connector", "Issue": "Idle connector.",
                     "Detail": f"No service, job or function routes through it, and its {connector['min_instances']}–{connector['max_instances']} {connector['machine_type']} instances bill around the clock.",
                     "Fix": f"gcloud compute networks vpc-access connectors delete {connector['name']} --region={connector['region']} --project={connector['project_id']}", "_status": INVESTIGATION})
    return rows


def api_cost_workloads(run, project_id, job_locations):
    """The project's services and jobs from the Cloud Run v2 API as cost facts (``api_services`` reads ingress; this reads the templates)."""
    found, services, jobs = {}, run.projects().locations().services(), run.projects().locations().jobs()
    request = services.list(parent=f"projects/{project_id}/locations/-")
    while request:
        response = request.execute() or {}
        for data in response.get("services") or []:
            w = cost_facts(project_id, data, data.get("name"), FUNCTION_2 if (data.get("labels") or {}).get(FUNCTIONS_LABEL) == "cloudfunctions" else SERVICE)
            found[(project_id, w["location"], w["name"])] = w
        request = services.list_next(previous_request=request, previous_response=response)
    for location in sorted(job_locations):
        request = jobs.list(parent=f"projects/{project_id}/locations/{location}")
        while request:
            response = request.execute() or {}
            for data in response.get("jobs") or []:
                w = cost_facts(project_id, data, data.get("name"), JOB)
                found[(project_id, w["location"], "job:" + w["name"])] = w
            request = jobs.list_next(previous_request=request, previous_response=response)
    return found


def api_connectors(vpcaccess, project_id, regions):
    """The project's connectors from the VPC Access API, per region the inventory showed one in."""
    found, collection = [], vpcaccess.projects().locations().connectors()
    for region in sorted(regions):
        request = collection.list(parent=f"projects/{project_id}/locations/{region}")
        while request:
            response = request.execute() or {}
            for data in response.get("connectors") or []:
                found.append(connector_facts({"data": data, "link": f"//vpcaccess.googleapis.com/{data.get('name')}", "project_id": project_id, "region": region}))
            request = collection.list_next(previous_request=request, previous_response=response)
    return found


def named_by_id(workloads, connectors, project_ids):
    """The facts with projects named by ID: the inventory names connectors by project *number*
    (``//vpcaccess.googleapis.com/projects/123/…``, as it does API keys and secrets), and the report names projects by ID like every other
    check — a workload's short connector reference (``projects/<id>/…``) must meet the connector's key too."""
    def rename(text):
        parts = str(text or "").split("/")
        if len(parts) > 1 and parts[0] == "projects" and parts[1] in project_ids:
            parts[1] = project_ids[parts[1]]
        return "/".join(parts)
    for w in workloads.values():
        w["project_id"] = project_ids.get(w["project_id"], w["project_id"])
        w["connector"] = rename(w["connector"])
    for c in connectors:
        c["project_id"] = project_ids.get(c["project_id"], c["project_id"])
        c["key"] = rename(c["key"])
    return workloads, connectors


def refresh_cost_facts(workloads, connectors, credentials, skipped):
    """Every project's workloads and connectors re-read from the Cloud Run v2 and VPC Access APIs (the inventory lags changes by hours; a
    deleted connector or a service moved to Direct VPC egress must clear on the next scan). The inventory's copy stands where a read is refused."""
    by_project = {}
    for w in workloads.values():
        by_project.setdefault(w["project_id"], []).append(w)
    run = None
    for project_id in sorted(by_project):
        run = run or gcp.api_build("run", "v2", credentials=credentials)
        try:
            fresh = api_cost_workloads(run, project_id, {w["location"] for w in by_project[project_id] if w["kind"] == JOB})
        except Exception as e:
            skipped.add(project_id, e, detail="Cloud Run services and jobs: the API read failed; the inventory's copy was used, which can lag changes by hours")
            continue
        gen2 = {(w["location"], w["name"]) for w in by_project[project_id] if w["kind"] == FUNCTION_2}
        for w in fresh.values():
            if (w["location"], w["name"]) in gen2:
                w["kind"] = FUNCTION_2
        workloads = {k: w for k, w in workloads.items() if w["project_id"] != project_id}
        workloads.update(fresh)
    connector_projects = {}
    for c in connectors:
        connector_projects.setdefault(c["project_id"], set()).add(c["region"])
    vpcaccess = None
    for project_id, regions in sorted(connector_projects.items()):
        vpcaccess = vpcaccess or gcp.api_build("vpcaccess", "v1", credentials=credentials)
        try:
            fresh = api_connectors(vpcaccess, project_id, regions)
        except Exception as e:
            skipped.add(project_id, e, detail="VPC Access connectors: the API read failed; the inventory's copy was used, which can lag a deletion by hours")
            continue
        connectors = [c for c in connectors if c["project_id"] != project_id] + fresh
    return workloads, connectors


def check_serverless_cost(scope, scope_id, job_id, *, sink):
    """Writes *Serverless Cost Hygiene*: the scope's services, jobs, gen-2 functions and connectors from the inventory, then each project's
    from the Cloud Run v2 and VPC Access APIs."""
    print(f"💸 [{job_id}] Checking {COST_CHECK} under {scope} {scope_id}...")
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        grouped = by_kind(list_assets(asset_client, parent, COST_TYPES))
    except Exception as e:
        logging.error(f"[{job_id}] {COST_CHECK}: could not list under {parent}: {e}")
        sink.write_finding(job_id, COST_CHECK.replace(" ", "_"), {"Check": COST_CHECK, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped = NotChecked(COST_CHECK)
    workloads, connectors = cost_workloads(grouped), [connector_facts(f) for f in grouped.get("connectors", [])]
    if any(c["project_id"].isdigit() for c in connectors) or any(w["project_id"].isdigit() for w in workloads.values()):
        try:
            workloads, connectors = named_by_id(workloads, connectors, project_ids_by_number(asset_client, parent))
        except Exception as e:
            skipped.add(parent, e, detail="project names: the project search failed; the projects named by number stay so")
    workloads, connectors = refresh_cost_facts(workloads, connectors, credentials, skipped)
    write_rows(sink, job_id, COST_CHECK, serverless_cost_rows(workloads, connectors), COST_ALL_CLEAR)
    skipped.write(sink, job_id)

