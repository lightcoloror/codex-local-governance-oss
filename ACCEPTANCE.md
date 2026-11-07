# Version 0.1.1 bounded acceptance

Date: 2026-11-07. Acting tool: Codex; exact runtime model independently unverified.

Windows CPython 3.13.5: 62 offline synthetic tests passed, no skips. This includes
the prior public edition's 39 checks and 23 checks for relocation, hash drift,
path escape, duplicate IDs, wrapper/catalog/proposal disagreement, source
provenance, invalid dates and attempts to promote missing native review into
runtime success. The parent test harness blocks socket resolution/connections.
An existing process-scoped Windows temporary-directory adapter was used only
inside a disposable test root; no ACL or system security setting was changed.
An initial direct pytest run hit WinError 5 creating its temporary directory;
that environment failure is not a failing contract assertion or native test pass.

An independent fresh venv installed the wheel offline from existing dependency
cache. Four installed checks passed from a working directory without source:
import origin, CLI help, default bundled validation and versions. All 69 Python/
JSON/Markdown package files match the wheel and candidate bytes. The environment
does not inherit system packages or a source PYTHONPATH.

Installed versions: attrs 26.1.0, jsonschema 4.26.0,
jsonschema-specifications 2025.9.1, referencing 0.37.0,
rfc3339-validator 0.1.4, rpds-py 2026.9.1 and six 1.17.0.

The result proves only metadata/schema/local byte consistency. It does not prove
native source/runtime interoperability, facts, live freshness, lifecycle
transitions, event delivery, approval or publication. Optional native review
Owners are not distributed. No network, actual tool launch, private inventory,
real content, customer information, service or media processing was used in
these tests. Secret scanning found no matches; source/license review retains
the Apache first-party scope and external-package license boundaries.
