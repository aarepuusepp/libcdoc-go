# Implementation boundaries — libcdoc-go 2.0.8

See the [README](../README.md) for the current API and format matrix.

CDOC1 XML, software RSA/EC/PKCS#12 and browser client-unwrapping APIs have
regression coverage. Standalone CDOC2 writes standard EC/RSA encoding,
HKDF-SHA256, OAEP-SHA256, nonempty key labels and zlib TAR; legacy encodings
remain read-only. [Reference fixtures](../cdoc/testdata/cdoc2-reference/README.md)
provide independent checks.

Configured Key Capsule ECC/RSA flows are implemented. Live RIA acceptance is
separate. SID/MID Key Shares external recovery remains blocked on verified proof
profiles. Draft schemas/exported APIs and older completion notes are not evidence
of production readiness. Do not enable them based only on mock tests.

[Release notes](../RELEASE-NOTES.md) record user-confirmed corrected P-384 output
in DigiDoc4 and standalone CDOC2 roundtrip in Digisign with EID-PD 2.1.10.
This does not certify every card, recipient type or live server.
