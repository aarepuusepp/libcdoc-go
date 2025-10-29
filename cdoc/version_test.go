package cdoc

import (
	"testing"
)

func TestDetectVersion(t *testing.T) {
	tests := []struct {
		name         string
		algorithmURI string
		expected     Version
	}{
		{"CDOC 1.1", "http://www.w3.org/2009/xmlenc11#aes256-gcm", Version11},
		{"CDOC 1.0", "http://www.w3.org/2001/04/xmlenc#aes128-cbc", Version10},
		{"Unknown", "http://example.com/unknown", Version10}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectVersion(tt.algorithmURI)
			if result != tt.expected {
				t.Errorf("DetectVersion(%s) = %v, want %v", tt.algorithmURI, result, tt.expected)
			}
		})
	}
}

func TestIsCDOC11(t *testing.T) {
	tests := []struct {
		name         string
		algorithmURI string
		expected     bool
	}{
		{"CDOC 1.1", "http://www.w3.org/2009/xmlenc11#aes256-gcm", true},
		{"CDOC 1.0", "http://www.w3.org/2001/04/xmlenc#aes128-cbc", false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCDOC11(tt.algorithmURI)
			if result != tt.expected {
				t.Errorf("IsCDOC11(%s) = %v, want %v", tt.algorithmURI, result, tt.expected)
			}
		})
	}
}

func TestVersion_String(t *testing.T) {
	if string(Version10) != "1.0" {
		t.Errorf("Version10 = %s, want '1.0'", string(Version10))
	}

	if string(Version11) != "1.1" {
		t.Errorf("Version11 = %s, want '1.1'", string(Version11))
	}
}

