# CyberSentinel UEBA — Dependency Audit

Read-only audit, 2026-10-21. No package was installed, removed or upgraded. No
manifest, lock file or application code was modified.

## 1. Four version concepts — never interchangeable

This audit keeps four things apart. Conflating them is the most common way a
dependency audit misleads.

| Concept | Meaning | Available here? |
|---|---|---|
| **Declared** | The constraint written in a manifest | ✅ both stacks |
| **Locked** | The exact version a lock file resolves to | ✅ frontend only |
| **Installed** | What actually ran in the environment | ❌ **production unknown** |
| **Latest** | Newest published | ✅ queried 2026-10-21 |

**Installed versions for production are unrecoverable.** The deployment host was
decommissioned and no virtualenv exists in the repository. Nothing below states
what production ran. A laptop column appears where a package happens to be
present in the local macOS Python 3.9 — that is **not** the deployment
environment and must not be read as one.

### Sources

| Data | Source | Date |
|---|---|---|
| Frontend locked versions | `package-lock.json` v3, 103 entries | repository |
| Frontend advisories | `npm audit --package-lock-only` → npm registry | 2026-10-21 |
| Frontend latest | `npm view <pkg> version` | 2026-10-21 |
| Python latest | PyPI JSON API (`pypi.org/pypi/<pkg>/json`) | 2026-10-21 |
| **Python advisories** | **OSV.dev API** (`api.osv.dev/v1/query`) | 2026-10-21 |
| Usage analysis | Static import scan, all `.py` | repository |

---

## 2. Python — declared vs latest

No lock file exists for Python, so there is no locked column.

| Package | Declared | Latest (2026-10-21) | Latest within range? | Imported in |
|---|---|---|---|---|
| `flask` | `>=3.0,<4.0` | 3.1.3 | ✅ | 3 files |
| `flask-cors` | `>=4.0,<5.0` | **6.0.5** | ❌ **range caps at 4.x** | 2 files |
| `pyyaml` | `>=6.0,<7.0` | 6.0.3 | ✅ | 8 files |
| `requests` | `>=2.31,<3.0` | 2.34.2 | ✅ | 1 file |
| `pyjwt` | `>=2.8,<3.0` | 2.15.1 | ✅ | 1 file |
| `cryptography` | `>=42.0` *(unbounded)* | 50.0.2 | ✅ | **0 files** |
| `orjson` | `>=3.9,<4.0` | 3.13.0 | ✅ | 2 files |
| `geoip2` | `>=4.7,<6.0` | 5.3.0 | ✅ | 1 file |
| `numpy` | `>=1.26,<3.0` | 2.5.4 | ✅ | 8 files |
| `pandas` | `>=2.1,<3.0` | **3.0.6** | ❌ range caps at 2.x | **0 files** |
| `h5py` | `>=3.10,<4.0` | 3.16.0 | ✅ | 2 files |
| `scikit-learn` | `>=1.4,<2.0` | 1.9.1 | ✅ | 1 file (**runtime-critical**, §5 F3) |
| `tqdm` | `>=4.66,<5.0` | 4.70.1 | ✅ | **0 files** |
| `joblib` | `>=1.3,<2.0` | 1.6.0 | ✅ | 4 files |
| `torch` | `>=2.2,<3.0` | 2.14.1 | ✅ | 2 files |
| `faiss-cpu` | `>=1.7,<2.0` | 1.15.1 | ✅ | 2 files |
| `hdbscan` | `>=0.8.33,<0.9` | 0.8.44 | ✅ | 1 file |

**Method note.** Latest was taken from the PyPI JSON API, not from
`pip index versions`. The local interpreter is Python 3.9, and `pip index` filters
to 3.9-compatible releases — it reports numpy 2.0.2 where the true latest is
2.5.4, and torch 2.8.0 where it is 2.14.1. Using the local pip would have
understated how far behind the declared ranges sit.

---

## 3. Python advisories — OSV.dev, evidence-based

With no lock file and no recoverable installed versions, the honest test is:
**what does each declared range admit?** Each package was queried at its range
floor and at the highest version the range allows.

| Package | Advisories at range floor | At highest allowed | Resolved by upgrading within range? |
|---|---|---|---|
| `torch` 2.2.0 | **23** | 0 at 2.14.1 | ✅ yes |
| `pyjwt` 2.8.0 | **27** | 0 at 2.15.1 | ✅ yes |
| `cryptography` 42.0.0 | **15** | 0 at 50.0.2 | ✅ yes |
| **`flask-cors` 4.0.0** | **10** | **6 at 4.0.2** | ❌ **NO — see below** |
| `requests` 2.31.0 | 6 | 0 at 2.34.2 | ✅ yes |
| `orjson` 3.9.0 | 4 | 0 at 3.13.0 | ✅ yes |
| `flask` 3.0.0 | 2 | 0 at 3.1.3 | ✅ yes |
| `scikit-learn` 1.4.0 | 2 | 0 at 1.9.1 | ✅ yes |
| `tqdm` 4.66.0 | 2 | 0 at 4.70.1 | ✅ yes |
| `pyyaml`, `geoip2`, `numpy`, `pandas`, `h5py`, `joblib`, `faiss-cpu`, `hdbscan` | 0 | 0 | — |

**Interpretation.** For every package except `flask-cors`, a plain
`pip install -r requirements.txt` today resolves to the top of the range, which
OSV reports clean. The floors are only reachable if something pins lower. **This
is not evidence that production was clean** — production's versions are unknown.

### flask-cors — the one range that blocks its own fix

Six advisories remain at **4.0.2**, the highest version `<5.0` permits. Confirmed
by querying each version directly:

| Version | Advisories |
|---|---|
| 4.0.2 | 6 |
| 5.0.0 | 6 |
| 5.0.1 | 6 |
| **6.0.0** | **0** |
| 6.0.5 (latest) | 0 |

Three distinct issues, each listed twice (GHSA + PYSEC), all **MODERATE**, all
fixed only in **6.0.0**:

| Advisory | Issue |
|---|---|
| GHSA-43qf-4rqw-9q2g / PYSEC-2026-1383 | Improper handling of case sensitivity |
| GHSA-7rxf-gvfg-47g4 / PYSEC-2026-1384 | Improper regex path matching |
| GHSA-8vgw-p6qm-5gr7 / PYSEC-2026-1385 | Inconsistent CORS matching |

All three are CORS-matching correctness faults — an origin that should be refused
may be accepted. Relevance depends on the deployed CORS configuration, which
`ueba_config.yaml` ties to the dashboard bind address. With
`host: "0.0.0.0"` and `auth.enforce: false`, CORS is not the primary control
anyway. **Real, evidence-backed, and requires a declared-range change to fix.**

---

## 4. Frontend — declared, locked, latest

Locked versions are exact; this is the best-evidenced part of the audit.

| Package | Declared | **Locked** | Latest | Role |
|---|---|---|---|---|
| `vite` | `^5.4.0` | **5.4.21** | 8.3.5 | Build tool (dev dependency) |
| `globe.gl` | `^2.46.1` | **2.46.1** | 2.46.2 | Only runtime dependency |
| `three` | transitive | **0.184.0** | 0.186.1 | 3D engine |
| `esbuild` | transitive | **0.21.5** | 0.28.2 | Bundled by Vite |
| `rollup` | transitive | **4.60.3** | 4.64.12 | Bundled by Vite |
| `postcss` | transitive | **8.5.14** | 8.5.31 | Bundled by Vite |
| `nanoid` | transitive | **3.3.12** | 6.0.2 | Toolchain internal |
| `source-map-js` | transitive | **1.2.1** | 1.2.2 | Toolchain internal |

103 lock entries, 49 of them optional platform binaries. **One** runtime
dependency ships to the browser; everything else is build toolchain.

**Installed:** `node_modules` is absent locally; no frontend install state exists
to inspect.

### Verified frontend vulnerabilities — 5 (4 high, 1 moderate)

| Package | Locked | Severity | Advisory | Fix |
|---|---|---|---|---|
| `vite` | 5.4.21 | **high** | depends on vulnerable `esbuild` | `vite@8.3.5` — **3 major versions** |
| `esbuild` | 0.21.5 | moderate | [GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99) — dev server lets any site issue requests and read responses | via Vite major |
| `postcss` | 8.5.14 | **high** | [GHSA-fxqj-rqcc-2cmp](https://github.com/advisories/GHSA-fxqj-rqcc-2cmp), [GHSA-r28c-9q8g-f849](https://github.com/advisories/GHSA-r28c-9q8g-f849) — `sourceMappingURL` path traversal | non-breaking |
| `nanoid` | 3.3.12 | **high** | [GHSA-28wg-ghj8-5hjv](https://github.com/advisories/GHSA-28wg-ghj8-5hjv), [GHSA-2v37-7h3g-55p8](https://github.com/advisories/GHSA-2v37-7h3g-55p8) — generators can loop indefinitely | non-breaking |
| `source-map-js` | 1.2.1 | **high** | [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q) — event-loop DoS | non-breaking |

### Exposure — all five are build-time only

None reaches the browser. Production is static files served by Flask from
`dashboard/dist/`.

- **`esbuild`** affects `vite dev` only; this project builds with `vite build`.
- **`postcss`, `source-map-js`** run at build time against this repository's own
  CSS. There is no attacker-controlled input path.
- **`nanoid`** is toolchain-internal.

**Real advisories, low practical risk in this deployment model.** They will still
appear in any customer-facing scan of the repository, which is reason enough to
clear the three that fix without a breaking change.

---

## 5. Usage findings

### F1 — Missing runtime dependencies (**verified, high impact**)

`reportlab` and `openpyxl` are imported but **absent from `requirements.txt`**:

- `ueba_report_render.py:208-210` → `openpyxl`
- `ueba_report_render.py:291-297` → `reportlab`
- `RENDERERS` (`:519-525`) advertises `pdf` and `xlsx` unconditionally
- `install_ueba.sh:487-489` installs from `requirements.txt` only

Imports are guarded (`:211-213` raises a clear `RuntimeError`), so it degrades
rather than crashes — but the UI offers two export formats that fail on a clean
install. Affects RFP 34/35/36/37/38/39/40/62.

### F2 — Unused dependencies (**verified**)

| Package | Evidence | Assessment |
|---|---|---|
| `pandas` | Zero occurrences outside `requirements.txt` | **Unused.** Heavyweight; also constrains numpy resolution |
| `tqdm` | Zero occurrences outside `requirements.txt` | **Unused.** Trivial size |
| `cryptography` | Zero imports, but `requirements.txt:19-22` documents it as the RS256/JWKS dependency | **Not currently used.** Deliberate forward declaration — only HS256 is reachable (`ueba_auth.py:71,126-127`). Not accidental |

### F3 — `scikit-learn` is runtime-critical despite one import (**verified**)

Imported only in `ueba_trainer.py:44-45`, which makes it look training-only. It is
not: `ueba_models/isolation_forest.py:65-66` calls `joblib.load()` on a pickled
sklearn estimator, which **requires sklearn present to deserialise**. Removing it
from a runtime install breaks detection at engine start.

### F4 — Documented Python version is wrong (**verified**)

Documentation states 3.12; the real floor is **3.10**. Eight modules use
`X | None` annotations without `from __future__ import annotations`:
`ueba_dashboard_server.py`, `ueba_engine.py`, `ueba_preprocessor.py`,
`ueba_trainer.py`, `ueba_watchlist.py`, `ueba_models/autoencoder.py`,
`ueba_models/clusterer.py`, `ueba_models/fp_suppressor.py`. Only `ueba_auth.py`
carries the `__future__` import. No 3.11- or 3.12-only feature was found.

**No `python_requires` is declared** — no `setup.py`, `pyproject.toml` or
`setup.cfg` exists.

### F5 — Compatibility risks (**identified, not verified by test**)

| Risk | Detail |
|---|---|
| `torch>=2.2,<3.0` | Spans 2.2 → 2.14. `torch.load`'s `weights_only` default changed at 2.6, and `ueba_models/autoencoder.py:160` passes no such argument — behaviour differs across the range |
| `numpy>=1.26,<3.0` | Spans the NumPy 2.0 ABI break; `faiss-cpu`, `torch`, `h5py`, `hdbscan` all carry compiled extensions |
| `hdbscan>=0.8.33,<0.9` | Small project, builds from source on some platforms, historically sensitive to the numpy/sklearn pair |
| `pandas>=2.1,<3.0` | pandas 3.0 is released and excluded by the cap. Moot — unused |
| `vite` 5 → 8 | Three major versions; config and plugin API changes expected |

### F6 — No Python lock file (**verified**)

Ranges only; no `requirements.lock`, pip-tools output or hashes. The frontend has
`package-lock.json`; the backend has no equivalent. Two installs a month apart can
differ, and what production ran is unrecoverable.

---

## 6. Documented stack vs verified

| Documented | Verified |
|---|---|
| Python 3.12 | Floor is **3.10**; undeclared (F4) |
| Flask | ✅ used |
| scikit-learn | ✅ used — **runtime**, not training-only (F3) |
| PyTorch | ✅ used; CPU wheels installed deliberately |
| HDBSCAN | ✅ used |
| FAISS CPU | ✅ used |
| HDF5 | ✅ via `h5py` |
| SQLite | ✅ standard library — correctly not declared |
| JavaScript | ✅ vanilla ES modules, one runtime dependency |
| Vite | ✅ locked 5.4.21 |

Accurate apart from the Python version.

---

## 7. Limitations of this audit

1. **Production installed versions are unrecoverable.** Everything in §3 describes
   what ranges *admit*, not what ran.
2. **No runtime verification.** Nothing was installed, so it is unknown whether
   `pip install -r requirements.txt` resolves to a working set today — the numpy
   2.0 boundary plus four compiled extensions make that a real question.
3. **Advisory data is a point-in-time snapshot** (2026-10-21) from OSV.dev and the
   npm registry. Neither is exhaustive.
4. **No transitive analysis for Python.** Without a lock file the transitive set
   cannot be enumerated. The frontend transitive tree is fully enumerated.
5. **Local Python 3.9 cannot run this codebase** (F4), so no import-level
   verification was possible.

---

## 8. Proposed changes — FOR APPROVAL, none applied

| ID | Proposal | Rationale | Risk | Effort |
|---|---|---|---|---|
| **P1** | Add `reportlab` and `openpyxl` to `requirements.txt` | F1 — two advertised formats fail without them | None, additive | Minutes |
| **P2** | `npm audit fix` (non-breaking only) | Clears `postcss`, `nanoid`, `source-map-js` | Low — patch-level, lock file only | Minutes |
| **P3** | Raise `flask-cors` to `>=6.0,<7.0` | **Only way to clear 6 advisories** — 4.x and 5.x are all affected; fixed in 6.0.0 | Medium — major bump; CORS behaviour changed, which is the point. Needs a config review | Hours |
| **P4** | Generate a Python lock file with hashes before the Utho rebuild | F6 — makes the new install reproducible and gives future audits an installed column | None | Hours |
| **P5** | Declare `python_requires = ">=3.10"` | F4 — nothing currently stops a 3.9 install that fails at import | Low | Hours |
| **P6** | Remove `pandas` and `tqdm` | F2 — unused; `pandas` also constrains numpy | Low — verify in a scratch environment | Minutes |
| **P7** | Pass `weights_only=True` to `torch.load` and narrow the torch range | F5 — behaviour differs across the declared span | Medium — needs a load test against existing `.pt` files | Hours |
| **P8** | Add `pip-audit` to a development workflow | Makes §3 repeatable rather than a one-off | None | Hours |
| **P9** | **Defer** the Vite 5 → 8 upgrade | Only advisory needing a breaking change; affects a dev server not run in production | — | Deferred |

**Suggested order:** P1 → P2 → P4 before the rebuild. P3 and P5 next. P6, P7, P8
after. P9 deferred until Utho is stable.

**On P3 specifically:** this is the only Python finding where upgrading within the
declared range does not help. It is also a major version bump whose changelog is
about CORS matching behaviour — exactly what the service depends on. It should be
approved deliberately, not bundled with routine patching.
