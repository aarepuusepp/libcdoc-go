module cdoc-test

go 1.24.2

require github.com/aarepuusepp/libcdoc-go/v2 v2.0.0

replace github.com/aarepuusepp/libcdoc-go/v2 => ../../

require (
	github.com/google/flatbuffers v24.3.25+incompatible // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	software.sslmate.com/src/go-pkcs12 v0.6.0 // indirect
)
