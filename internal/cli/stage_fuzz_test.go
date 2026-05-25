package cli

import (
	"bytes"
	"testing"
)

func FuzzExtractPkgNameFromTarball(f *testing.F) {
	seeds := []string{
		"",
		"not-gzip-data",
		"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = extractPkgNameFromTarball(r)
	})
}
