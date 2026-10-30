package central_test

import (
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/central"
)

func TestValidateNOfN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		shareCount  int
		minRequired int
		wantErr     bool
	}{
		{name: "valid two of two", shareCount: 2, minRequired: 2},
		{name: "valid three of three", shareCount: 3, minRequired: 3},
		{name: "too few shares", shareCount: 1, minRequired: 1, wantErr: true},
		{name: "min below two", shareCount: 2, minRequired: 1, wantErr: true},
		{name: "count exceeds min", shareCount: 3, minRequired: 2, wantErr: true},
		{name: "count below min", shareCount: 2, minRequired: 3, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := central.ValidateNOfN(tc.shareCount, tc.minRequired)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
