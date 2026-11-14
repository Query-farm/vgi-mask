# Data Masking & De-identification examples

| Notebook | Question | One-parameter experiment |
| --- | --- | --- |
| [01 · Join keys and redacted labels](01_join_keys_and_redacted_labels.ipynb) | Which join preserves distinct orders and exact amounts? | Order key version `v1` → `v2` |
| [02 · A round trip does not prove encryption](02_a_round_trip_does_not_prove_encryption.ipynb) | Can recovery succeed even when a value passed through unchanged? | Profile `digits` → `alnum` |

Open either notebook on GitHub to read its saved outputs, or use its **Open in Colab** button and run the install cell, then Run All. The shared package supplies branding, SVG plots and isolated SQL setup. Both examples are independent and contain all inputs inline: a single downloaded notebook is enough. No worker checkout, Rust build, account, fixture download or real credentials are needed. Actual hosted Colab has not been tested; fresh preloaded Python 3.12 notebook-only executions validate bootstrap and compatible-library preservation.

## Locked local runner

Install [uv](https://docs.astral.sh/uv/), then from this directory:

```sh
uv sync --locked --extra runner
uv run --locked --extra runner vgi-notebooks
```

Python 3.11+ is supported; uv can install it. The notebook installs only the core [shared tools v0.3.11](https://github.com/Query-farm/vgi-example-notebooks/tree/v0.3.11); `[runner]` adds local execution dependencies. Haybarn 2.0.0rc11 runs the visible native release attachment:

```sql
ATTACH 'mask' (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-mask@v0.4.0');
```

VGI verifies and caches the platform release binary. Initial package, extension and worker downloads require internet access; all masking operations use local inline data. Deliberately upgrade the tag and rerun both defaults and experiments when changing worker versions.

Shared `connect(globals())` creates an in-memory connection with empty temporary `secret_directory`, persistent SQL secrets disabled, and no default JupySQL connection autoload. Cleanup closes the worker connection and removes that directory. The fake literal keys are intentionally visible; this isolation is not a production key-storage design.

The shared runner creates temporary kernels and only replaces saved notebooks after complete success. Default publication retains native SVG MIME and writes content-addressed `charts/` assets referenced by ordinary GitHub image links. Optional review SVG/PNG files, logs and experiment copies are ignored under `artifacts/` or `validation/`.

Optional editor kernel:

```sh
uv run --locked --extra runner python -m ipykernel install --user --name mask-examples --display-name "Python (vgi-mask notebooks)"
```

## Separate experiments

```sh
uv run --locked --extra runner vgi-notebooks 01_join_keys_and_redacted_labels.ipynb --parameters '{"ORDER_KEY_VERSION":"v2"}' --output-dir validation/key-v2
uv run --locked --extra runner vgi-notebooks 02_a_round_trip_does_not_prove_encryption.ipynb --parameters '{"FORMAT_PROFILE":"alnum"}' --output-dir validation/alnum
```

Overrides require a separate output directory; a failing execution leaves both the default and previous successful experiment unchanged. Restart and run all after editing parameters manually.

In notebook 01, the aligned customer mapping follows the orders' selected public key version while another mapping stays at v1. The aligned result preserves the reference; fixed-v1 joins expose an incomplete migration. Redaction takes no key, so its collisions and inflated joined amount remain unchanged. This is compatibility analysis, not a key-rotation implementation. Restore `v1` for defaults.

Notebook 02 retains nine invented rows, including one NULL, and uses the deliberately public `public-demo-fpe-key`. The worker's `digits` profile selects ten digit symbols and requires six selected characters; `alnum` uses 62 ASCII letters/digits and requires four. Below that domain minimum the worker passes the value through. Switching profiles changes eligibility and ciphertext, while all eight present values recover exactly under the matching profile/key. Structural punctuation and length remain fixed; `alnum` does not preserve each letter/digit position or case. Restore `digits` for defaults. Only those two profiles are investigated; the example does not validate every supported format or establish an anonymization guarantee.

## Surface coverage

Actual v0.4.0 runtime discovery reports four scalar names and no tables/views. [coverage.json](coverage.json) maps interpreted, visibly executed examples to all four: `mask_token` and `mask_redact` in notebook 01, `mask_fpe` and `mask_unfpe` in notebook 02. Complete released catalog exports, current registration evidence and raw-JSON execution receipts live under [coverage/](coverage/).

Released coverage is **4/4**, and current-interface coverage at public source `8df17fd6b718a0f693b29cafbfa66f73926751f0` is **4/4** after a complete registration/diff review. Current changes only add examples/metadata and a metadata test; parameters, execution bodies and dependency locks are unchanged. Exact runtime counts are **four released / zero current-main**: the notebook does not execute an unbuilt current source checkout. Existing successful [source CI 43572772203](https://github.com/Query-farm/vgi-mask/actions/runs/43572772203) is reused for this notebook-only change; source builds and test suites were not repeated.

## Provenance and interpretation

All six customers, eleven orders, `example.test` addresses and USD-cent amounts
are invented directly in visible SQL. The fixture has no capture date. One order
has a missing email, another an email absent from the customer reference; neither
is silently assigned an identity. Exact strings are used without normalization.

The keys `public-demo-key-v1` and `public-demo-key-v2` are deliberately public,
nonsecret demonstration strings. Plaintext stays visible for the teaching
comparison. This notebook does not create a protected export or demonstrate
production secret storage. Real keys in SQL can appear in history/logs; operational
key management and access control are outside this example.

All tokenization and redaction calls go through the real worker. SQL materializes
the extracts, joins on the full 32-character token strings, counts distinct order
IDs separately from joined rows, and sums integer cents before converting to USD.
The deliberately wrong redacted join shows that display labels can collide and
multiply rows. Token uniqueness is checked only for this fixture; no general
collision impossibility is claimed. A zero sum from the mismatched join means no
matched rows, not zero-value source orders.

Deterministic tokens preserve equality and expose frequencies. Partial redaction
still exposes visible characters, lengths and domains. Neither the example nor
its passing relational checks establishes anonymization or a privacy guarantee.
Identity normalization and compatible key versions must be designed before real
joins; missing values should stay distinct from valid identifiers.

Worker behavior and caveats are documented in the [pinned v0.4.0 README](https://github.com/Query-farm/vgi-mask/blob/v0.4.0/README.md); shared notebook conventions and execution behavior are in the [shared standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.11/docs/standard.md).
