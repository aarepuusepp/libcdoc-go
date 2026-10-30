//go:build cgo

package key

import "testing"

func TestMatchedPrivateKeyRequiresID(t *testing.T) {
	// No native context is needed: reject an absent CKA_ID before accessing token.
	var context PKCS11Context
	if _, err := context.findPrivateKeyByID(nil); err == nil {
		t.Fatal("empty CKA_ID must not select an arbitrary private key")
	}
}
