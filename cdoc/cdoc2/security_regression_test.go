package cdoc2

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"
	"testing"
)

func TestParseHeader_RejectsInvalidMagic(t *testing.T) {
	_, _, err := ParseHeader(strings.NewReader("NOTCDOC2HEADER"))
	if err == nil {
		t.Fatal("expected parse error for invalid magic")
	}
}

func TestParseHeader_RejectsTruncatedHeader(t *testing.T) {
	truncated := []byte(Label)
	truncated = append(truncated, 0, 0, 0, 10) // claims 10 byte header
	_, _, err := ParseHeader(bytes.NewReader(truncated))
	if err == nil {
		t.Fatal("expected parse error for truncated header")
	}
}

func TestDecompressGzip_RejectsExpansionBomb(t *testing.T) {
	prev := maxDecompressedGzipBytes
	maxDecompressedGzipBytes = 4096
	t.Cleanup(func() { maxDecompressedGzipBytes = prev })

	bomb := makeGzipRepeatedZeros(t, 8192)
	_, err := decompressGzip(bomb)
	if err == nil {
		t.Fatal("expected decompression limit error")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecompressGzip_AllowsSmallPayload(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("small-payload"))
	_ = zw.Close()

	out, err := decompressGzip(buf.Bytes())
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(out) != "small-payload" {
		t.Fatalf("got %q", out)
	}
}

func makeGzipRepeatedZeros(t *testing.T, expandedBytes int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.CopyN(zw, zeroReader{}, int64(expandedBytes)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestDecompressZlibLimit(t *testing.T) {
	prev := maxDecompressedGzipBytes
	maxDecompressedGzipBytes = 4096
	t.Cleanup(func() { maxDecompressedGzipBytes = prev })
	for _, size := range []int{100, 8192} {
		var b bytes.Buffer
		z := zlib.NewWriter(&b)
		_, _ = z.Write(bytes.Repeat([]byte{0}, size))
		_ = z.Close()
		out, err := decompressGzip(b.Bytes())
		if size > 4096 {
			if err == nil {
				t.Fatal("accepted zlib expansion bomb")
			}
		} else if err != nil || len(out) != size {
			t.Fatal("zlib decode failed", err)
		}
	}
}
