# libcdoc-go 2.0.7

- Support interoperable local CDOC2 ECC/RSA containers: TLS curve points, SHA-256 KDF, RSA-OAEP-SHA256 and zlib payloads.
- Preserve historical SPKI/SHA512, RSA PKCS1v1.5 and gzip containers.
- Validate against independent Open-EID Java containers and independently decoded writer output.
- Fix CI formatting checks and update pinned GitHub Actions.

Public test keys are copied from Open-EID commit daff207f719b4c1cfc4a1138733a4f8c531524c6. DER SHA256 verified against GitHub:
- EC256: 3C83B5B5BDF33F5B511E7778F17033215FB5CBAEFDBE0436B32BF9BBD9EF5A44
- EC384: 6DAE5B765FC1F1FB73542DBD2C5354E0B984DDF29AD114D005A26A5C46616BCC
- RSA: A12A200DFE04DC16D85EA2BCD0245D9AC2080870A864284BB2A70B199C24B999

Real-card CDOC2 acceptance is pending. Central keyserver/SID/MID contract readiness is unchanged.
