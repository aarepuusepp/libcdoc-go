package crypto

import (
	"bytes"
	"testing"
)

func TestAddX923Padding(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		blockSize  int
		expected   []byte
		expectedLen int
	}{
		{
			name:       "pad 12 bytes",
			data:       "test",
			blockSize:  16,
			expected:   []byte{116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12},
			expectedLen: 12,
		},
		{
			name:       "pad 4 bytes",
			data:       "testtesttest",
			blockSize:  16,
			expected:   []byte{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 4},
			expectedLen: 4,
		},
		{
			name:       "pad 16 bytes (full block)",
			data:       "testtesttesttest",
			blockSize:  16,
			expected:   []byte{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16},
			expectedLen: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := &bytes.Buffer{}
			_, err := output.WriteString(tt.data)
			if err != nil {
				t.Fatal(err)
			}

			padLength, err := AddX923Padding(output, int64(len(tt.data)), tt.blockSize)
			if err != nil {
				t.Fatalf("AddX923Padding() error = %v", err)
			}
			if padLength != tt.expectedLen {
				t.Errorf("AddX923Padding() padLength = %v, want %v", padLength, tt.expectedLen)
			}

			got := output.Bytes()
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("AddX923Padding() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRemoveX923PaddingFromData(t *testing.T) {
	tests := []struct {
		name     string
		padded   []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "remove 12 bytes padding",
			padded:   []byte{116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12},
			expected: []byte("test"),
			wantErr:  false,
		},
		{
			name:     "remove 4 bytes padding",
			padded:   []byte{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 4},
			expected: []byte("testtesttest"),
			wantErr:  false,
		},
		{
			name:     "remove 16 bytes padding",
			padded:   []byte{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16},
			expected: []byte("testtesttesttest"),
			wantErr:  false,
		},
		{
			name:    "empty data",
			padded:  []byte{},
			wantErr: true,
		},
		{
			name:    "invalid padding (non-zero bytes)",
			padded:   []byte{116, 101, 115, 116, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RemoveX923PaddingFromData(tt.padded)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoveX923PaddingFromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.expected) {
				t.Errorf("RemoveX923PaddingFromData() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAddPKCS7Padding(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		blockSize  int
		expected   []byte
		expectedLen int
	}{
		{
			name:       "pad 12 bytes",
			data:       "test",
			blockSize:  16,
			expected:   []byte{116, 101, 115, 116, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12},
			expectedLen: 12,
		},
		{
			name:       "pad 4 bytes",
			data:       "testtesttest",
			blockSize:  16,
			expected:   []byte{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 4, 4, 4, 4},
			expectedLen: 4,
		},
		{
			name:       "pad 16 bytes (full block)",
			data:       "testtesttesttest",
			blockSize:  16,
			expected:   []byte{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			expectedLen: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := &bytes.Buffer{}
			_, err := output.WriteString(tt.data)
			if err != nil {
				t.Fatal(err)
			}

			padLength, err := AddPKCS7Padding(output, int64(len(tt.data)), tt.blockSize)
			if err != nil {
				t.Fatalf("AddPKCS7Padding() error = %v", err)
			}
			if padLength != tt.expectedLen {
				t.Errorf("AddPKCS7Padding() padLength = %v, want %v", padLength, tt.expectedLen)
			}

			got := output.Bytes()
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("AddPKCS7Padding() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRemovePKCS7PaddingFromData(t *testing.T) {
	tests := []struct {
		name     string
		padded   []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "remove 12 bytes padding",
			padded:   []byte{116, 101, 115, 116, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12},
			expected: []byte("test"),
			wantErr:  false,
		},
		{
			name:     "remove 4 bytes padding",
			padded:   []byte{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 4, 4, 4, 4},
			expected: []byte("testtesttest"),
			wantErr:  false,
		},
		{
			name:     "remove 16 bytes padding",
			padded:   []byte{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			expected: []byte("testtesttesttest"),
			wantErr:  false,
		},
		{
			name:    "empty data",
			padded:  []byte{},
			wantErr: true,
		},
		{
			name:    "invalid padding (wrong byte value)",
			padded:   []byte{116, 101, 115, 116, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 11},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RemovePKCS7PaddingFromData(tt.padded)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemovePKCS7PaddingFromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.expected) {
				t.Errorf("RemovePKCS7PaddingFromData() = %v, want %v", got, tt.expected)
			}
		})
	}
}

