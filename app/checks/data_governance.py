"""
Data governance (v18.4).

The Security Health Analytics Standard detectors and CIS Level-1 items for the
data plane, none of which the tool read before. Every item is a setting in
Cloud Asset Inventory — one listing per check under the scanned scope — plus
one IAM-policy search where the question is *who* may reach the data:

- **BigQuery Governance** (Security): datasets and tables open to ``allUsers``
  or ``allAuthenticatedUsers`` (Action Required), datasets whose time-travel
  window is below the seven-day default.
- **Cloud SQL Flags** (Security): the CIS §6 flag pack of each engine — MySQL
  (``local_infile``, ``skip_show_database``), PostgreSQL (the ``log_*`` family
  and pgAudit), SQL Server (external scripts, remote access, cross-database
  ownership chaining, contained-database authentication, user connections and
  options, trace flag 3625) — an unset flag read as its engine default.
- **AlloyDB Posture** (Reliability): automated and continuous backups, zonal
  primaries, public IP, TLS, the PostgreSQL log flags.
- **KMS Keys** (Security): symmetric keys without a rotation within 90 days,
  key rings and keys open to the public, principals holding both the admin and
  an encrypter/decrypter role (separation of duties).
- **API Keys** (Security): keys without an application restriction, without an
  API restriction, or older than 90 days.

Every check reaches a verdict or an all-clear row; a listing that fails is the
check's Error; a failed IAM search leaves that rule under *Projects not
checked* and the rest of the check standing.
"""
import logging
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from app.checks.gke_operations import ACTION_REQUIRED, INVESTIGATION, write_rows
from app.checks.network_edge import by_kind, list_assets, tail
from app.checks.not_checked import NotChecked
from app.config import SCOPES
from app.services import gcp

BIGQUERY_CHECK = "BigQuery Governance"
SQL_FLAGS_CHECK = "Cloud SQL Flags"
ALLOYDB_CHECK = "AlloyDB Posture"
KMS_CHECK = "KMS Keys"
API_KEYS_CHECK = "API Keys"
DATA_GOVERNANCE_CHECKS = (BIGQUERY_CHECK, SQL_FLAGS_CHECK, ALLOYDB_CHECK, KMS_CHECK, API_KEYS_CHECK)

BIGQUERY_TYPES = ["bigquery.googleapis.com/Dataset"]
BIGQUERY_IAM_TYPES = ["bigquery.googleapis.com/Dataset", "bigquery.googleapis.com/Table"]
SQL_TYPES = ["sqladmin.googleapis.com/Instance"]
ALLOYDB_TYPES = ["alloydb.googleapis.com/Cluster", "alloydb.googleapis.com/Instance"]
KMS_TYPES = ["cloudkms.googleapis.com/CryptoKey"]
KMS_IAM_TYPES = ["cloudkms.googleapis.com/KeyRing", "cloudkms.googleapis.com/CryptoKey"]
API_KEY_TYPES = ["apikeys.googleapis.com/Key"]

PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")
PUBLIC_QUERY = "memberTypes:(allUsers OR allAuthenticatedUsers)"
DEFAULT_TIME_TRAVEL_HOURS = 168
KEY_ROTATION_MAX_DAYS = 90
API_KEY_MAX_AGE_DAYS = 90
KMS_ADMIN_ROLE = "roles/cloudkms.admin"
KMS_CRYPTO_ROLES = ("roles/cloudkms.cryptoKeyEncrypterDecrypter", "roles/cloudkms.cryptoKeyEncrypter", "roles/cloudkms.cryptoKeyDecrypter")
KMS_ROLES_QUERY = "roles:(" + " OR ".join((KMS_ADMIN_ROLE,) + KMS_CRYPTO_ROLES) + ")"

BIGQUERY_ALL_CLEAR = "No dataset or table is open to allUsers or allAuthenticatedUsers, and every dataset keeps the seven-day time-travel window."
SQL_FLAGS_ALL_CLEAR = "Every Cloud SQL instance carries the CIS flag pack of its engine."
ALLOYDB_ALL_CLEAR = "Every AlloyDB cluster has automated and continuous backups, a regional primary, private IPs, TLS enforced and the PostgreSQL log flags."
KMS_ALL_CLEAR = "Every symmetric key rotates within 90 days, no key ring or key is public, and nobody both manages and uses a key."
API_KEYS_ALL_CLEAR = "Every API key is restricted to its applications and APIs and is younger than 90 days."

# --- the Cloud SQL flag packs (CIS §6) --------------------------------------------------------------------------------
# PostgreSQL message levels, least to most strict (fewer messages logged as the level rises); log_statement, least to most.
PG_LEVELS = ("debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice", "warning", "error", "log", "fatal", "panic")
PG_STATEMENT_LEVELS = ("none", "ddl", "mod", "all")
PG_VERBOSITY = ("terse", "default", "verbose")  # strictest first: "default or stricter" means terse or default


def _at_least(levels, value, floor):
    """``value`` is ``floor`` or stricter on an ordered scale (``levels`` least → most strict)."""
    try:
        return levels.index(str(value).lower()) >= levels.index(floor)
    except ValueError:
        return False


# (flag, engine default, expected text, test(value) -> ok, verdict, CIS item)
SQL_FLAG_PACKS = {
    "MYSQL": [
        ("local_infile", "on", "off", lambda v: str(v).lower() == "off", ACTION_REQUIRED, "6.1.3"),
        ("skip_show_database", "off", "on", lambda v: str(v).lower() == "on", INVESTIGATION, "6.1.2"),
    ],
    "POSTGRES": [
        ("log_connections", "off", "on", lambda v: str(v).lower() == "on", INVESTIGATION, "6.2.1"),
        ("log_disconnections", "off", "on", lambda v: str(v).lower() == "on", INVESTIGATION, "6.2.2"),
        ("log_error_verbosity", "default", "default or terse", lambda v: str(v).lower() in ("default", "terse"), INVESTIGATION, "6.2.3"),
        ("log_min_messages", "warning", "warning or stricter", lambda v: _at_least(PG_LEVELS, v, "warning"), INVESTIGATION, "6.2.4"),
        ("log_min_error_statement", "error", "error or stricter", lambda v: _at_least(PG_LEVELS, v, "error"), INVESTIGATION, "6.2.5"),
        ("log_min_duration_statement", "-1", "-1 (off: statements carry data)", lambda v: str(v) == "-1", INVESTIGATION, "6.2.6"),
        ("log_statement", "none", "ddl or stricter", lambda v: _at_least(PG_STATEMENT_LEVELS, v, "ddl"), INVESTIGATION, "6.2.7"),
        ("cloudsql.enable_pgaudit", "off", "on", lambda v: str(v).lower() == "on", INVESTIGATION, "6.2.8"),
    ],
    "SQLSERVER": [
        ("external scripts enabled", "off", "off", lambda v: str(v).lower() == "off", ACTION_REQUIRED, "6.3.1"),
        ("cross db ownership chaining", "off", "off", lambda v: str(v).lower() == "off", ACTION_REQUIRED, "6.3.2"),
        ("remote access", "on", "off", lambda v: str(v).lower() == "off", ACTION_REQUIRED, "6.3.3"),
        ("user connections", "0", "0 (non-limiting)", lambda v: str(v) == "0", INVESTIGATION, "6.3.4"),
        ("user options", "", "not set", lambda v: str(v) == "", INVESTIGATION, "6.3.5"),
        ("3625", "off", "on", lambda v: str(v).lower() == "on", INVESTIGATION, "6.3.6"),
        ("contained database authentication", "off", "off", lambda v: str(v).lower() == "off", ACTION_REQUIRED, "6.3.7"),
    ],
}
ALLOYDB_LOG_FLAGS = ("log_connections", "log_disconnections", "log_error_verbosity", "log_min_messages", "log_min_error_statement")


def engine_of(database_version):
    """``MYSQL`` / ``POSTGRES`` / ``SQLSERVER`` from ``MYSQL_8_0``, ``POSTGRES_15``, ``SQLSERVER_2019_STANDARD``; ``""`` otherwise."""
    version = str(database_version or "").upper()
    for engine in SQL_FLAG_PACKS:
        if version.startswith(engine):
            return engine
    return ""


def flag_values(instance):
    """``{flag: value}`` of an instance's ``settings.databaseFlags`` (a list of ``{name, value}``) or an AlloyDB ``databaseFlags`` map
    (a proto map from the inventory — a ``Mapping``, not a ``dict``)."""
    flags = (instance.get("settings") or {}).get("databaseFlags") if "settings" in instance else instance.get("databaseFlags")
    if isinstance(flags, Mapping):
        return {str(k): str(v) for k, v in flags.items()}
    return {str(f.get("name")): str(f.get("value", "")) for f in (flags or []) if f.get("name")}


def flag_findings(engine, flags):
    """``[(flag, current, expected, verdict, cis)]`` — the pack entries an instance fails (an unset flag is its engine default)."""
    found = []
    for flag, default, expected, ok, verdict, cis in SQL_FLAG_PACKS.get(engine, []):
        current = flags.get(flag, default)
        if not ok(current):
            found.append((flag, current if flag in flags else f"{default} (default)", expected, verdict, cis))
    return found


def sql_flag_rows(facts):
    """The *Cloud SQL Flags* rows; replicas inherit their primary's flags and are not repeated."""
    rows = []
    for fact in facts:
        data = fact["data"]
        if str(data.get("instanceType") or "").upper() == "READ_REPLICA_INSTANCE":
            continue
        engine, flags = engine_of(data.get("databaseVersion")), flag_values(data)
        for flag, current, expected, verdict, cis in flag_findings(engine, flags):
            wanted = {**flags, flag: expected.split(" ")[0] if flag != "user options" else ""}
            if flag == "user options":
                wanted.pop("user options", None)
            flag_list = ",".join(f"{k}={v}" for k, v in wanted.items() if v != "") or "<none>"
            rows.append({"Project": fact["project_id"], "Instance": fact["name"], "Engine": str(data.get("databaseVersion") or engine), "Flag": flag,
                         "Current": current, "Expected": expected, "Issue": f"CIS {cis}: {flag} is {current}, expected {expected}.",
                         "Fix": f"gcloud sql instances patch {fact['name']} --project={fact['project_id']} --database-flags={flag_list}  "
                                "# patch replaces the whole list: the flags already set are included",
                         "_status": verdict})
    return rows


# --- BigQuery Governance ----------------------------------------------------------------------------------------------

def dataset_public_entries(dataset):
    """The ``access`` entries of a dataset that admit the public: ``(role, member)``."""
    found = []
    for entry in dataset.get("access") or []:
        member = entry.get("specialGroup") or entry.get("iamMember") or ""
        if member in PUBLIC_MEMBERS:
            found.append((entry.get("role") or "READER", member))
    return found


def public_policy_rows(results):
    """``{resource: [(role, member)]}`` of the public bindings in IAM-policy search results."""
    found = {}
    for result in results:
        bindings = getattr(getattr(result, "policy", None), "bindings", None) or []
        for binding in bindings:
            for member in list(getattr(binding, "members", None) or []):
                if member in PUBLIC_MEMBERS:
                    found.setdefault(getattr(result, "resource", ""), []).append((getattr(binding, "role", ""), member))
    return found


def bigquery_resource(resource):
    """``(project_id, label, dataset_id, is_table)`` from ``//bigquery.googleapis.com/projects/P/datasets/D[/tables/T]``."""
    parts = resource.split("/")
    project_id = parts[parts.index("projects") + 1] if "projects" in parts else ""
    dataset_id = parts[parts.index("datasets") + 1] if "datasets" in parts and parts.index("datasets") + 1 < len(parts) else resource
    if "tables" in parts:
        return project_id, f"table {dataset_id}.{parts[-1]}", dataset_id, True
    return project_id, f"dataset {dataset_id}", dataset_id, False


def bigquery_rows(grouped, public_policies):
    rows, seen = [], set()

    def row(project_id, resource, issue, detail, fix, status):
        rows.append({"Project": project_id, "Resource": resource, "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

    for dataset in grouped.get("datasets", []):
        data, dataset_id = dataset["data"], (dataset["data"].get("datasetReference") or {}).get("datasetId") or dataset["name"]
        public = dataset_public_entries(data)
        if public:
            seen.add(dataset["project_id"] + "/" + dataset_id)
            grants = ", ".join(f"{member} as {role}" for role, member in public)
            row(dataset["project_id"], f"dataset {dataset_id}", "Dataset open to the public.", f"{grants}: anyone on the internet (or any Google account) reads it.",
                f"bq show --format=prettyjson {dataset['project_id']}:{dataset_id} > ds.json; remove the {public[0][1]} entry from access; bq update --source ds.json {dataset['project_id']}:{dataset_id}",
                ACTION_REQUIRED)
        hours = int(float(data.get("maxTimeTravelHours") or DEFAULT_TIME_TRAVEL_HOURS))
        if hours < DEFAULT_TIME_TRAVEL_HOURS:
            row(dataset["project_id"], f"dataset {dataset_id}", "Time travel shortened.", f"{hours} hours instead of {DEFAULT_TIME_TRAVEL_HOURS}: a dropped table or a bad DELETE is recoverable for that long only.",
                f"bq update --max_time_travel_hours={DEFAULT_TIME_TRAVEL_HOURS} {dataset['project_id']}:{dataset_id}", INVESTIGATION)
    for resource, grants in sorted(public_policies.items()):
        project_id, label, dataset_id, is_table = bigquery_resource(resource)
        if not is_table and f"{project_id}/{dataset_id}" in seen:
            continue  # the dataset's own ACL already said so
        target = f"{project_id}:{dataset_id}" + (f".{label.rsplit('.', 1)[-1]}" if is_table else "")
        row(project_id, label, ("Table" if is_table else "Dataset") + " open to the public.", ", ".join(f"{m} as {r}" for r, m in grants) + ".",
            f"bq remove-iam-policy-binding --member={grants[0][1]} --role={grants[0][0]} {target}", ACTION_REQUIRED)
    return rows


# --- AlloyDB Posture --------------------------------------------------------------------------------------------------

def alloydb_rows(grouped):
    rows = []

    def row(fact, cluster, instance, issue, detail, fix, status):
        rows.append({"Project": fact["project_id"], "Cluster": cluster, "Instance": instance, "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

    for cluster in grouped.get("clusters", []):
        data, name, location = cluster["data"], tail(cluster["name"]), cluster["region"]  # the API names clusters by their full path
        base = f"gcloud alloydb clusters update {name} --region={location} --project={cluster['project_id']}"
        if not (data.get("automatedBackupPolicy") or {}).get("enabled", False):
            row(cluster, name, "(cluster)", "Automated backups off.", "No daily backup: a bad migration or a deleted cluster is unrecoverable.", f"{base} --automated-backup-start-times=02:00 --automated-backup-days-of-week=MONDAY,TUESDAY,WEDNESDAY,THURSDAY,FRIDAY,SATURDAY,SUNDAY", ACTION_REQUIRED)
        if not (data.get("continuousBackupConfig") or {}).get("enabled", False):
            row(cluster, name, "(cluster)", "Continuous backup off.", "No point-in-time recovery.", f"{base} --enable-continuous-backup --continuous-backup-recovery-window-days=14", INVESTIGATION)
    for instance in grouped.get("instances", []):
        data, name = instance["data"], tail(instance["name"])
        cluster = tail(instance["link"], 3).split("/")[0] if "/clusters/" in instance["link"] else ""
        base = f"gcloud alloydb instances update {name} --cluster={cluster} --region={instance['region']} --project={instance['project_id']}"
        kind = str(data.get("instanceType") or "PRIMARY").upper()
        if kind == "PRIMARY" and str(data.get("availabilityType") or "").upper() == "ZONAL":
            row(instance, cluster, name, "Zonal primary.", "One zone's incident takes the database down.", f"{base} --availability-type=REGIONAL", INVESTIGATION)
        if (data.get("networkConfig") or {}).get("enablePublicIp", False):
            row(instance, cluster, name, "Public IP enabled.", "The instance answers on the internet; the Auth Proxy or private IP is the pattern.", f"{base} --no-assign-inbound-public-ip", INVESTIGATION)
        ssl_mode = str(((data.get("clientConnectionConfig") or {}).get("sslConfig") or {}).get("sslMode") or "ENCRYPTED_ONLY").upper()
        if ssl_mode != "ENCRYPTED_ONLY":
            row(instance, cluster, name, "TLS not enforced.", f"sslMode {ssl_mode}: unencrypted connections are accepted.", f"{base} --ssl-mode=ENCRYPTED_ONLY", INVESTIGATION)
        flags = flag_values(data)
        for flag, current, expected, verdict, cis in flag_findings("POSTGRES", flags):
            if flag in ALLOYDB_LOG_FLAGS:
                row(instance, cluster, name, f"{flag} is {current}.", f"CIS {cis}: expected {expected}.", f"{base} --database-flags={flag}={expected.split(' ')[0]}  # with the flags already set", INVESTIGATION)
    return rows


# --- KMS Keys ---------------------------------------------------------------------------------------------------------

def parse_duration_seconds(text):
    """``"7776000s"`` → 7776000; ``None`` when absent or unreadable."""
    try:
        return int(float(str(text).rstrip("s")))
    except (TypeError, ValueError):
        return None


def parse_time(text):
    if not text:
        return None
    try:
        value = str(text).strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def kms_rows(grouped, public_policies, role_results, now):
    rows = []

    def row(project_id, key, issue, detail, fix, status):
        rows.append({"Project": project_id, "Key": key, "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})

    for key_fact in grouped.get("cryptoKeys", []):
        data = key_fact["data"]
        if str(data.get("purpose") or "").upper() != "ENCRYPT_DECRYPT":
            continue  # asymmetric and MAC keys have no rotation
        if str((data.get("primary") or {}).get("state") or "ENABLED").upper() in ("DESTROYED", "DESTROY_SCHEDULED", "DISABLED"):
            continue
        ring, key_name = tail(key_fact["link"], 3).split("/")[0], tail(key_fact["name"])  # the API names keys by their full path
        location = key_fact["region"]
        period = parse_duration_seconds(data.get("rotationPeriod"))
        next_time = parse_time(data.get("nextRotationTime"))
        fix = (f"gcloud kms keys update {key_name} --keyring={ring} --location={location} --project={key_fact['project_id']} "
               f"--rotation-period={KEY_ROTATION_MAX_DAYS}d --next-rotation-time={(now + timedelta(days=1)):%Y-%m-%d}T00:00:00Z")
        if period is None:
            row(key_fact["project_id"], f"{ring}/{key_name}", "No rotation period.", "The key has never rotated automatically (CIS 1.10: every 90 days).", fix, INVESTIGATION)
        elif period > KEY_ROTATION_MAX_DAYS * 86400:
            row(key_fact["project_id"], f"{ring}/{key_name}", "Rotation period above 90 days.", f"{period // 86400} days (CIS 1.10: at most 90).", fix, INVESTIGATION)
        elif next_time is not None and next_time < now:
            row(key_fact["project_id"], f"{ring}/{key_name}", "Rotation overdue.", f"next rotation was due {next_time:%Y-%m-%d}.", fix, INVESTIGATION)
    for resource, grants in sorted(public_policies.items()):
        parts = resource.split("/")
        project_id = parts[parts.index("projects") + 1] if "projects" in parts else ""
        row(project_id, "/".join(parts[parts.index("keyRings") + 1:]).replace("cryptoKeys/", "") if "keyRings" in parts else resource, "Key ring or key open to the public.",
            ", ".join(f"{m} as {r}" for r, m in grants) + ".", f"gcloud kms keys remove-iam-policy-binding … --member={grants[0][1]} --role={grants[0][0]}", ACTION_REQUIRED)
    for result in role_results:
        bindings = getattr(getattr(result, "policy", None), "bindings", None) or []
        admins, users = set(), {}
        for binding in bindings:
            role, members = getattr(binding, "role", ""), list(getattr(binding, "members", None) or [])
            if role == KMS_ADMIN_ROLE:
                admins.update(members)
            elif role in KMS_CRYPTO_ROLES:
                for member in members:
                    users.setdefault(member, set()).add(role)
        resource = getattr(result, "resource", "")
        parts = resource.split("/")
        project_id = parts[parts.index("projects") + 1] if "projects" in parts else ""
        for member in sorted(admins & set(users)):
            row(project_id, tail(resource, 2), "Admin and user of the same keys.", f"{member} holds {KMS_ADMIN_ROLE} and {', '.join(sorted(users[member]))} on {tail(resource, 2)} (CIS 1.11: separation of duties).",
                f"gcloud … remove-iam-policy-binding --member={member} --role={sorted(users[member])[0]}  # or the admin role; keep one", INVESTIGATION)
    return rows


# --- API Keys ---------------------------------------------------------------------------------------------------------

def project_ids_by_number(asset_client, parent):
    """``{project number: project ID}`` under ``parent`` — one resource search. The inventory names API keys by project *number*
    (``//apikeys.googleapis.com/projects/123/…``), and the report names projects by ID like every other check."""
    found = {}
    for result in asset_client.search_all_resources(request={"scope": parent, "asset_types": ["cloudresourcemanager.googleapis.com/Project"]}):
        number = str(getattr(result, "project", "") or "").split("/")[-1]
        if number:
            found[number] = str(getattr(result, "name", "") or "").split("/")[-1]
    return found


def api_key_rows(grouped, now, project_ids=None):
    rows = []
    for key_fact in grouped.get("keys", []):
        data = key_fact["data"]
        project_id = (project_ids or {}).get(key_fact["project_id"], key_fact["project_id"])
        name = data.get("displayName") or data.get("uid") or key_fact["name"]
        uid = data.get("uid") or key_fact["name"]
        restrictions = data.get("restrictions") or {}
        created = parse_time(data.get("createTime"))
        base = f"gcloud services api-keys update {uid} --project={project_id}"

        def row(issue, detail, fix, status=INVESTIGATION):
            rows.append({"Project": project_id, "Key": name, "Created": created.strftime("%Y-%m-%d") if created else "unknown",
                         "Issue": issue, "Detail": detail, "Fix": fix, "_status": status})
        if not any(restrictions.get(k) for k in ("browserKeyRestrictions", "serverKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions")):
            row("No application restriction.", "Any website, server or app that obtains the key can use it (CIS 1.13).", f"{base} --allowed-referrers=<sites>  # or --allowed-ips / --allowed-application")
        if not restrictions.get("apiTargets"):
            row("No API restriction.", "The key reaches every API the project has enabled (CIS 1.14).", f"{base} --api-target=service=<service>")
        if created is not None and (now - created).days > API_KEY_MAX_AGE_DAYS:
            row("Older than 90 days.", f"created {created:%Y-%m-%d}, {(now - created).days} days ago (CIS 1.15).", f"gcloud services api-keys create --display-name={name} …  # then delete {uid}")
    return rows


# --- the checks -------------------------------------------------------------------------------------------------------

def _search(asset_client, parent, query, asset_types=None):
    request = {"scope": parent, "query": query}
    if asset_types:
        request["asset_types"] = list(asset_types)
    return list(asset_client.search_all_iam_policies(request=request))


def _run(check, types, rows_of, scope, scope_id, job_id, sink, all_clear, searches=(), project_names=False):
    """``searches``: ``[(label, query, asset_types)]`` — the IAM-policy searches the rules need; a failed one is noted, the rest stands.
    ``project_names``: the rules want project IDs for the project numbers in the asset names (``results["projects"]``)."""
    parent = f"{scope}s/{scope_id}"
    try:
        credentials, _ = gcp.auth_default(scopes=SCOPES)
        asset_client = gcp.asset_client(credentials)
        grouped = by_kind(list_assets(asset_client, parent, types))
    except Exception as e:
        logging.error(f"[{job_id}] {check}: could not list under {parent}: {e}")
        sink.write_finding(job_id, check.replace(" ", "_"), {"Check": check, "Finding": [{"Error": str(e)}], "Status": "Error"})
        return
    skipped, results = NotChecked(check), {}  # a failed search is recorded against the scanned scope: the check has no project list
    for label, query, asset_types in searches:
        try:
            results[label] = _search(asset_client, parent, query, asset_types)
        except Exception as e:
            results[label] = []
            skipped.add(parent, e, detail=f"{label} rule: the IAM policy search failed")
    if project_names and grouped:
        try:
            results["projects"] = project_ids_by_number(asset_client, parent)
        except Exception as e:
            skipped.add(parent, e, detail="project names: the resource search failed; the rows name projects by number")
    write_rows(sink, job_id, check, rows_of(grouped, results), all_clear)
    skipped.write(sink, job_id)


def check_bigquery_governance(scope, scope_id, job_id, *, sink):
    print(f"📊 [{job_id}] Checking {BIGQUERY_CHECK} under {scope} {scope_id}...")
    _run(BIGQUERY_CHECK, BIGQUERY_TYPES, lambda g, r: bigquery_rows(g, public_policy_rows(r.get("public access", []))), scope, scope_id, job_id, sink,
         BIGQUERY_ALL_CLEAR, searches=[("public access", PUBLIC_QUERY, BIGQUERY_IAM_TYPES)])


def check_sql_flags(scope, scope_id, job_id, *, sink):
    print(f"🗄️ [{job_id}] Checking {SQL_FLAGS_CHECK} under {scope} {scope_id}...")
    _run(SQL_FLAGS_CHECK, SQL_TYPES, lambda g, r: sql_flag_rows(g.get("instances", [])), scope, scope_id, job_id, sink, SQL_FLAGS_ALL_CLEAR)


def check_alloydb_posture(scope, scope_id, job_id, *, sink):
    print(f"🗄️ [{job_id}] Checking {ALLOYDB_CHECK} under {scope} {scope_id}...")
    _run(ALLOYDB_CHECK, ALLOYDB_TYPES, lambda g, r: alloydb_rows(g), scope, scope_id, job_id, sink, ALLOYDB_ALL_CLEAR)


def check_kms_keys(scope, scope_id, job_id, *, sink, now=None):
    print(f"🔑 [{job_id}] Checking {KMS_CHECK} under {scope} {scope_id}...")
    now = now or datetime.now(timezone.utc)
    _run(KMS_CHECK, KMS_TYPES, lambda g, r: kms_rows(g, public_policy_rows(r.get("public access", [])), r.get("role separation", []), now), scope, scope_id, job_id, sink,
         KMS_ALL_CLEAR, searches=[("public access", PUBLIC_QUERY, KMS_IAM_TYPES), ("role separation", KMS_ROLES_QUERY, None)])


def check_api_keys(scope, scope_id, job_id, *, sink, now=None):
    print(f"🔑 [{job_id}] Checking {API_KEYS_CHECK} under {scope} {scope_id}...")
    now = now or datetime.now(timezone.utc)
    _run(API_KEYS_CHECK, API_KEY_TYPES, lambda g, r: api_key_rows(g, now, r.get("projects")), scope, scope_id, job_id, sink, API_KEYS_ALL_CLEAR, project_names=True)
