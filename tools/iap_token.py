#!/usr/bin/env python3
"""Print a token that passes Identity-Aware Proxy in front of a CloudGauge web service.

IAP accepts a JWT signed by a service account that holds ``roles/iap.httpsResourceAccessor`` on the
service (https://cloud.google.com/iap/docs/authentication-howto). This mints one through the IAM
Credentials API with the signed-in gcloud identity, which needs ``roles/iam.serviceAccountTokenCreator``
on that service account. Google-issued ID tokens (``gcloud auth print-identity-token``) do not pass IAP
on Cloud Run with its Google-managed OAuth client, so this is the way in for ``curl``, scripts and
``tools/demo_gif.py``.

The token's audience is ``BASE_URL/*``: it is good for every path of that URL and for that URL only (a
canary tag URL needs its own), for ``--ttl`` seconds (default and maximum 3600).

Usage::

    python tools/iap_token.py SERVICE_ACCOUNT_EMAIL BASE_URL [--ttl SECONDS]

    TOKEN=$(python tools/iap_token.py cloudgauge-sa@my-project.iam.gserviceaccount.com https://cloudgauge-....run.app)
    curl -H "Authorization: Bearer $TOKEN" https://cloudgauge-....run.app/api/status/JOB/SCOPE_ID

Only the standard library and gcloud are needed (``certifi`` is used for the TLS roots when it is
installed, which it is in the project's virtualenv).
"""
import argparse
import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

SIGN_JWT_URL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:signJwt"
MAX_TTL_SECONDS = 3600


def gcloud_access_token():
    """The signed-in gcloud identity's access token (the caller of signJwt)."""
    try:
        result = subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Could not get an access token from gcloud ({error}); run `gcloud auth login` first.") from None
    return result.stdout.strip()


def _ssl_context():
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def mint_iap_token(service_account, base_url, ttl=MAX_TTL_SECONDS, access_token=None):
    """A JWT signed by ``service_account`` that IAP accepts for every path under ``base_url``."""
    ttl = max(1, min(int(ttl), MAX_TTL_SECONDS))
    now = int(time.time())
    claims = {"iss": service_account, "sub": service_account, "aud": base_url.rstrip("/") + "/*", "iat": now, "exp": now + ttl}
    request = urllib.request.Request(
        SIGN_JWT_URL.format(sa=service_account),
        data=json.dumps({"payload": json.dumps(claims)}).encode(),
        headers={"Authorization": f"Bearer {access_token or gcloud_access_token()}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=_ssl_context()) as response:
            return json.load(response)["signedJwt"]
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:600]
        hint = ("" if error.code != 403 else
                f"\nYour gcloud account needs roles/iam.serviceAccountTokenCreator on {service_account}:\n"
                f"  gcloud iam service-accounts add-iam-policy-binding {service_account} "
                f"--member=user:YOU@example.com --role=roles/iam.serviceAccountTokenCreator")
        raise SystemExit(f"signJwt failed with HTTP {error.code}: {detail}{hint}") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("service_account", help="the service account that signs the token (it needs roles/iap.httpsResourceAccessor)")
    parser.add_argument("base_url", help="the web service's URL, e.g. https://cloudgauge-....run.app")
    parser.add_argument("--ttl", type=int, default=MAX_TTL_SECONDS, help=f"seconds the token is valid (default and maximum {MAX_TTL_SECONDS})")
    args = parser.parse_args(argv)
    print(mint_iap_token(args.service_account, args.base_url, args.ttl))


if __name__ == "__main__":
    sys.exit(main())
