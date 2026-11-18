<!--
Title: a Conventional Commit line — it becomes the squash commit and the changelog entry.
  feat: … | fix: … | docs: … | ci: … | build: … | refactor: … | test: … | chore: …
  A breaking change to the stability surface (env vars, Terraform variables, roles/APIs, the BigQuery schema,
  CSV columns, check names) is `feat!:` and says what breaks.
-->

## What and why



## How it was verified

- [ ] The suite is green on 3.11 and 3.13 (CI), new behaviour has a test
- [ ] A check's change was run against a real scope (say which kind: organization / folder / project)
- [ ] Nothing internal: no shortlinks, hostnames or analytics names (the suite's guardrail checks)

## Release note line

<!-- One line for RELEASE_NOTES.md, or "none" for a change nobody deploying would notice. -->

## Stability surface

<!-- "unchanged", or what changed in env vars, Terraform variables, roles/APIs, the BigQuery schema, CSV columns, check names. -->
