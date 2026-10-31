# v2.0.8

- CDOC2 writers now assign a nonempty public recipient label when the caller
  omits it. DigiDoc4/libcdoc rejects an otherwise supported recipient with an
  empty key_label as an unsupported algorithm or recipient type.
- Explicit labels are preserved. Certificate common names, subject serial
  numbers, or neutral type labels supply fallbacks; passwords and symmetric
  keys are never used as labels.
- Regression coverage includes the direct Writer API, Builder-generated
  RSA/ECC headers, and Digisign encryption integration tests.

Interoperability check (2026-10-31): DigiDoc4 4.11.1.5434 opens a corrected
standalone P-384 sample without the unsupported-recipient warning. The user
confirmed successful ID-card decryption and the exact expected compatibility.txt
contents in DigiDoc4. This verifies the tested inline P-384 path, not every
recipient type. Existing files must be regenerated: their header
is authenticated and cannot safely be patched in place.

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


## Installed-release acceptance (2026-10-31)

After installing EID-PD 2.1.10, the user confirmed successful encryption and
subsequent decryption of a CDOC 2.0 standalone container in Digisign, and
successful ID-card personal-data reading in Visitor. The release set is:
reader/package 2.1.10, extension 2.1.6, web SDK 1.0.2, libcdoc-go 2.0.8,
libopenpace-go 1.1.3, Digisign backend 2.0.7/UI 0.0.8, Visitor Vue 2.1.6.

This is user-reported real-environment acceptance. The latest report does not
identify the browser, card profile or contact/NFC transport, so it does not
establish a new browser/card/transport matrix. Earlier separately confirmed
NFC and DigiDoc4 results retain their original scope. Central transfer-server
and Smart-ID/Mobile-ID acceptance are separate from standalone CDOC2.
