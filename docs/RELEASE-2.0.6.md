# 2.0.6

Includes CDOC2 central-service development, transport bounds and redirect restrictions, RSA/ECC key capsules, N-of-N share reconstruction, PKCS#11 signing, and regression coverage.

Auth-token signatures require a valid certificate and matching identity. ES256 uses JWS 64-byte R||S encoding. Unsigned/mock fallback tokens are rejected.

Smart-ID/Mobile-ID key-share recovery is unavailable: the RP proof adapter is not verified against the pinned RIA draft contracts. The former mock flow signed different bytes from the generated SD-JWT. CreateFromSignature and the RP authentication step return ErrExternalProofProfileUnsupported. Direct JWS signing and local prefetched-share cryptography remain testable; mock results do not establish RIA interoperability.

Live RIA environments, TLS trust, proof profiles, operational contracts, and real SID/MID acceptance remain pending. This release does not claim production readiness for these external workflows.
