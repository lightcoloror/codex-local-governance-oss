# Offline local governance

Build and inspect metadata-only tool manifests and validate local task, action,
workflow and routing contract documents. This public edition extracts reusable
checks from a private governance snapshot; it contains no actual tool inventory,
task queue, customer material, private history or machine configuration.

Python 3.10+; run from a clone:

```sh
python -m venv .venv
# Activate the venv using your platform's standard command.
python -m pip install -e ".[test]"
local-governance --pack-root examples/metadata-pack build
local-governance --pack-root examples/metadata-pack validate
local-governance --pack-root examples/metadata-pack doctor-all --workspace-root examples/synthetic-workspace
governance-contract --schema governance_assets/schemas/local-tool-task-receipt.v1.schema.json --document examples/task-receipt.synthetic.json --input-root examples
governance-bundle
python -m pytest -q
```

`build` writes only the selected pack's generated manifest files. `validate`,
`doctor` and `doctor-all` read declared files; they do not launch tools, connect
to a service, grant execution authority or prove current online status. Tool IDs
are configurable, unique safe path segments. Missing required fixture files block
the metadata check. The two example tools and the retired example are synthetic.

The installed manifest command uses its bundled, hash-pinned validator and schema;
it does not depend on a private sibling repository. `--pack-root` is explicit.
`--rcp-root` remains an advanced compatibility input; only the exact pinned public
edition bytes are accepted. Manifest commands are metadata, never executed here.

`governance-contract` checks JSON Schema with an empty reference Registry, verifies
a top-level payload hash when present, and checks every exact `{path, sha256}`
reference against local bytes under an explicit input root. Absolute or escaping
reference paths are blocked. No remote reference retrieval occurs. Hashes prove
byte identity, not factual truth. The referenced example capsule/slice/handoff/
envelope are inert bytes, not complete executable task contracts. Their individual
schemas are not recursively asserted by the receipt verifier.

## Scope

Included: generic discovery/task/action/workflow schemas, configurable manifest
build/validation/read-only doctor, synthetic request/receipt examples, and offline
payload/reference integrity checks. Published schemas retain their original
versions. A structural pass does not prove lifecycle transitions, business
completion, evidence truth, approval or publication permission.

The routing schema is the fixed historical 1.9.0 contract, for inspection and
structural validation only. Content-specific route ordering, deployed Skills,
current route selection and full routing validation belong to the self-media
workflow edition. They are not replaced by this package. The original workspace
task compiler/action executor and Registry projection are deliberately omitted;
there is no task execution command, background worker, UI or network service.

Use `PROVENANCE.json` and `THIRD_PARTY_NOTICES.md` for fixed sources, extraction
and licensing. Local tests are offline synthetic checks, not deployed-tool tests.

## Portable contract reference bundle

Version 0.1.1 includes `contracts/portable/v1/portable-contract-bundle.v1.json`
and the same bytes as installed package resources. `governance-bundle` reads the
installed copy; `governance-bundle --bundle-root contracts/portable/v1` reads an
explicit local copy. It verifies local hashes, schema structure, metadata
boundaries and four synthetic example schemas. It never installs or runs the
named tools, fetches sources, discovers a workspace, routes a job or grants
approval. Pin the root bundle digest from a trusted source separately; a
self-consistent rewritten bundle is not a signature or proof of origin.

Seven stable IDs preserve the original contract meanings: material manifest,
evidence bundle, content brief, review packet, service profile, closure run and
local tool event. See [bundle scope](contracts/portable/v1/README.md) and
`AVAILABILITY.json`. The optional native review renderer/lifecycle integration
is not distributed. Its frozen public intake schema remains a consumer copy;
another project's review receipt cannot replace its native behavior.
