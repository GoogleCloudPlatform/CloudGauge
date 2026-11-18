# Security policy

CloudGauge reads a Google Cloud organization's configuration with the roles listed in the README and writes its findings to a bucket the deployer owns. A vulnerability is anything that lets the deployed services be made to read or write beyond that — a request that bypasses Identity-Aware Proxy or the worker's caller verification, an identifier that reaches a bucket key or a command unvalidated, a report that executes what a resource name contains — or anything that leaks a finding to someone the deployer did not grant access to.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

- Report it through [g.co/vulnz](https://g.co/vulnz), Google's intake for security issues in its open-source projects. The Google Security Team responds within 5 working days.
- Or use the repository's private channel: **Security › Report a vulnerability** on GitHub, which opens a draft security advisory visible only to the maintainers.

Either way, coordination and the fix happen in a GitHub security advisory of this repository; the fix ships in the next release, with a line in `RELEASE_NOTES.md` once the advisory is published.

This project is not an officially supported Google product and is **not eligible** for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

## Supported versions

Fixes land on the newest release only; deploy from the latest tag (the README's *Updating an Existing Deployment* section says how).

## What the deployment itself relies on

The README's *Request hardening* section lists the request checks every deployment makes, and *Privacy & API Attribution* what the services read and never read. Dependencies are pinned in `requirements.txt`; Dependabot and the repository's secret and code scanning run on every pull request.
