# v2.0.5

Adds the client-side transport-key API required by EID-PD:
`PrepareClientUnwrap`, `UnwrapTransportKeyWithPKCS11`,
`UnwrapTransportKeyWithToken` and `FinishClientDecrypt`.

- Supports the existing CDOC 1.0/1.1 and CDOC2 inline-recipient flows.
- Matches PKCS#11 certificates to private keys using a nonempty, unambiguous
  CKA_ID; ECDH derives a session secret without exporting the private key.
- Preserves the v2.0.4 Token interface. Optional DigestToken carries the
  ConcatKDF digest; legacy tokens reject unsupported digests explicitly.
- Fixes CDOC2 inline EC certificate matching (DER vs raw key-server points).
- Rejects invalid versions, points and recipient types, clears intermediate
  key material, and avoids allocating TAR content solely from its declared size.

Validation: full Go tests and vet with CGO enabled and disabled; software
RSA/EC round trips, legacy-token compatibility, malformed requests, wrong-key
and tampered-payload rejection. Physical PKCS#11 card/PIN acceptance remains
separate; software tests do not establish hardware interoperability.

Unrelated in-progress server/key-share changes are not part of this release.
