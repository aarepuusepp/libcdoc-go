# Independent CDOC2 interoperability fixtures

Public test containers and TEST-ONLY private keys copied unchanged from
https://github.com/open-eid/cdoc2-java-ref-impl at commit
`daff207f719b4c1cfc4a1138733a4f8c531524c6`.
Containers: `test/testvectors/{ec_simple,ec_256_simple,rsa_simple}.cdoc2`.
Keys: `cdoc2-cli/keys/{expired/cdoc2client_expired_priv.key,cdoc2client_256_priv.key,rsa_priv.pem}`.
MIT license retained in LICENSE. These public keys are never production credentials.
The containers were produced by an independent implementation, not libcdoc-go.

`legacy-{ec,rsa}.cdoc2` are synthetic test-only
fixtures generated with libcdoc-go commit `b7ecfea3b581605e15d7700a67bbf29814bf5c55`. Their plaintext is
`legacy libcdoc-go CDOC2`. They verify historical SPKI/SHA512, RSA PKCS1v1.5
and gzip compatibility. They reuse the public upstream EC-256 and RSA keys listed above. No personal card keys or application data are included.
