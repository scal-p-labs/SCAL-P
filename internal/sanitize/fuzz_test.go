package sanitize

import (
	"testing"
)

func FuzzSanitizePackageName(f *testing.F) {
	seeds := []string{
		"",
		"lodash",
		"@scope/pkg",
		"..",
		".",
		"a/../b",
		"a/b/c",
		"../../../etc/passwd",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, name string) {
		err := SanitizePackageName(name)
		if err != nil {
			return
		}
		if name == "" {
			t.Errorf("expected error for empty name")
		}
	})
}

func FuzzValidatePMArgs(f *testing.F) {
	seeds := []string{
		"",
		"lodash",
		"--save-dev",
		"install",
		"add",
		"rm -rf /",
		"$(cat /etc/passwd)",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, arg string) {
		args := []string{arg}
		err := ValidatePMArgs(args)
		if err != nil {
			return
		}
	})
}

func FuzzHasTraversal(f *testing.F) {
	seeds := []string{
		"",
		".",
		"..",
		"a/b/c",
		"../foo",
		"./foo",
		"/absolute/path",
		"a/../../b",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		HasTraversal(path)
	})
}
