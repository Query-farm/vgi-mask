# Join keys and redacted labels

[Open the executed notebook](01_join_keys_and_redacted_labels.ipynb). It compares
joins on deterministic tokens, mismatched key versions and redacted display text,
then reconciles row counts and joined amounts against a synthetic source reference.

## Run from this folder

Install [uv](https://docs.astral.sh/uv/), then:

```bash
uv sync --frozen
uv run python execute.py
```

The locked environment uses Python 3.13–3.14 and published Haybarn 2.0.0rc11.
The notebook's literal connection downloads the pinned native worker:

```sql
ATTACH 'mask' (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-mask@v0.4.0');
```

VGI verifies the release checksum and caches the platform binary. Published assets
cover Apple-silicon macOS and Linux x86-64/arm64. First use needs network access to
package indexes, GitHub and community extensions. No worker checkout, source build,
account credentials or globally registered kernel is required. This entire folder
runs independently of the repository. To upgrade, change the literal release tag
and repeat both executions and checks.

For an editor, register and select the notebook environment:

```bash
uv run python -m ipykernel install --user --name mask-examples \
  --display-name "Python (vgi-mask notebooks)"
```

Restart and run all after editing parameters. Setup, plots and generated-prose
source are folded; parameters, connection and analytical SQL remain visible.
The runner creates a temporary kernel, uses this folder as cwd and saves only after
success. Parameter overrides require a separate output directory, which receives
branding, helpers and environment/documentation companions. Generated artifacts
are ignored; saved default outputs remain embedded in the main notebook.

## Key-version experiment

```bash
uv run python execute.py --parameters '{"ORDER_KEY_VERSION":"v2"}' \
  --output-dir validation/key-v2
```

`ORDER_KEY_VERSION` accepts `v1` or `v2`, default `v1`. Orders use the selected
public test string. The aligned customer mapping uses that same version; another
mapping stays fixed at v1. Predict which joins retain their matches and compare
both charts. The aligned result must preserve the source reference, while the
fixed-v1 join exposes an incomplete migration. Redaction takes no key, so its
collisions and join inflation stay fixed. Restore `v1` for the saved default.
This is an experiment about compatibility, not a key-rotation implementation.

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

See the pinned [worker README](https://github.com/Query-farm/vgi-mask/blob/78bf19998a20a7865f49f084fd31fac44119cbe4/README.md)
for the wider API and limitations, and [STANDARD.md](STANDARD.md) for notebook conventions.
