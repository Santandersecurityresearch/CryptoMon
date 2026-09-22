# Vendored CycloneDX schema

`bom-1.6.schema.json` and the two schemas it references, taken verbatim from
[CycloneDX/specification](https://github.com/CycloneDX/specification/tree/master/schema).

They are here so that `tests/test_cbom.py` validates the generated CBOM
against the **published specification** rather than against our own idea of
it. A CBOM's entire value is that somebody else's tooling can read it; a test
that checks the document looks the way we meant it to look would confirm
nothing about that.

Vendored rather than fetched at test time because the suite must run offline
and must not depend on GitHub being up, and because a schema that can change
underneath a green build is not a fixture.

To update: replace the three files, re-run the suite, and record the spec
version change in the commit message.
