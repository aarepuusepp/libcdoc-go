package bounds_test

import (
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/bounds"
)

func TestLen_RejectsOversize(t *testing.T) {
	t.Parallel()
	if err := bounds.Len("container", bounds.MaxContainerBytes+1, bounds.MaxContainerBytes); err == nil {
		t.Fatal("expected limit error")
	}
	if err := bounds.Len("field", 10, bounds.MaxCapsuleFieldBytes); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLen_RejectsNegative(t *testing.T) {
	t.Parallel()
	if err := bounds.Len("share", -1, bounds.MaxShareIDLen); err == nil {
		t.Fatal("expected negative length error")
	}
}

func TestConstantsAreDocumentedLimits(t *testing.T) {
	t.Parallel()
	if bounds.MaxDecompressedTarEntry <= bounds.MaxHeaderBytes {
		t.Fatal("decompressed tar limit should exceed header limit")
	}
	if bounds.MaxTransactionIDLen < bounds.MinTransactionIDLen {
		t.Fatal("transaction id max must be >= min")
	}
}
