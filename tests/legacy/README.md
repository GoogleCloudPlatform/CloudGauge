# Frozen reference modules

The parity tests run these upstream files side by side with the `app` package, against the same fakes. Don't edit them: they are the definition of "unchanged behavior". Ruff skips this folder.

| File | Upstream source | SHA-256 |
|---|---|---|
| `cloudgauge_legacy.py` | `main:cloudgauge.py`, the monolith this package replaces (byte-identical except the final newline) | `4d4b87da79f69c13a4c7a2742b979c3c7f873437704c1340555b93209e155623` |
| `cloudgauge_beta_v1.py` | `beta:cloudgauge_beta_v1.py` at commit `5f2285e` (2025-12-02): `main` plus four checks (`check_cloud_sql_security`, `check_vpc_configuration`, `check_storage_ubla`, `check_vm_external_ips`) | `3b7338d8dd45209f755743cc167eb72a3b9e85ebd7cc4a2a23be8ab4c9d7a81b` |

Both import `vertexai`, which is no longer a dependency. `helpers.import_legacy` gives them a stub, and the fixtures in `conftest.py` point it at the Gemini fake.

Known upstream gap: `cloudgauge_beta_v1.py` never added its four checks to the category map in `_read_all_findings_from_gcs`, so its reports silently drop their findings. The port adds them to `app.checks.categories.CATEGORY_MAP` (Security & Identity).
