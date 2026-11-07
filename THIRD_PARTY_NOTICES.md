# Source and license notices

The owner-authorized public edition is Apache-2.0. Original private repositories
and their histories are not distributed or relicensed in place.

Manifest validation helpers and the manifest schema are derived from first-party
`research-content-production` (Apache-2.0), fixed source identified in
`PROVENANCE.json`. Selected helper functions retain their implementation, with
remote JSON Schema retrieval explicitly disabled. The schema's distribution
identity points to this public edition. No portable bundle is implied or fetched.

JSON Schema validation uses the separately installed `jsonschema` and `referencing`
libraries (MIT); date-time validation uses `rfc3339-validator` (MIT). Their source
and binaries are not vendored. Setuptools and pytest are build/test dependencies,
not embedded application code. No fonts, music, models or media are distributed.
