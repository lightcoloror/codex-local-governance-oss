# Source and license notices

The owner-authorized public edition is Apache-2.0. Original private repositories
and their histories are not distributed or relicensed in place.

Manifest validation helpers and the manifest schema are derived from first-party
`research-content-production` (Apache-2.0), fixed source identified in
`PROVENANCE.json`. Selected helper functions retain their implementation, with
remote JSON Schema retrieval explicitly disabled. The schema's distribution
identity points to this public edition. Version 0.1.1 includes an offline
portable metadata bundle; it is never fetched or used to execute a named tool.

Additional first-party generic schemas and synthetic fixtures are extracted
from the same fixed `research-content-production` source. Its source LICENSE
is Apache-2.0 and includes the retained attribution `Copyright 2025 Bojie Li`.
The original license text remains in this repository. Adapted files and source
hashes are identified in `contracts/portable/v1/SOURCE-PROVENANCE.json` and its
README. No private inventory or historical operational receipts are included.
References to separately distributed AGPL-3.0-only VKP/Gateway files do not
copy or relicense their implementation. Other named optional projects are
references only, without an asserted public availability or distribution grant.

JSON Schema validation uses the separately installed `jsonschema` and `referencing`
libraries (MIT); date-time validation uses `rfc3339-validator` (MIT). Their source
and binaries are not vendored. Setuptools and pytest are build/test dependencies,
not embedded application code. No fonts, music, models or media are distributed.
