package sanitize_test

import (
	"testing"

	"scal-p/internal/sanitize"
)

func TestSanitizePackageName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"lodash", false},
		{"@scope/pkg", false},
		{"is-odd", false},
		{"@types/node", false},
		{"pkg-with-hyphens", false},
		{"pkg_with_underscores", false},
		{"pkg.with.dots", false},
		{"1234", false},
		{"", true},
		{".", true},
		{"..", true},
		{"../../etc/passwd", true},
		{"a/b/c", false},
		{"../foo", true},
		{"foo/../bar", true},
		{"foo/.", true},
		{"./foo", true},
		{"/absolute/path", true},
		{"@scope/../other", true},
		{"foo//bar", true},
		{"foo/", true},
		{"/", true},
	}
	for _, tt := range tests {
		err := sanitize.SanitizePackageName(tt.name)
		if tt.wantErr && err == nil {
			t.Errorf("SanitizePackageName(%q) = nil, want error", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("SanitizePackageName(%q) = %v, want nil", tt.name, err)
		}
	}
}

func TestHasTraversal(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"node_modules/lodash", false},
		{"node_modules/@scope/pkg", false},
		{"/home/user/.pnpm/pkg@1/node_modules/pkg", false},
		{"node_modules/../../etc/passwd", true},
		{"../foo", true},
		{"foo/../bar", true},
		{".", true},
		{"./foo", true},
		{"foo/.", true},
		{"", false},
		{"/", false},
		{"/etc/passwd", false},
		{"node_modules/..", true},
		{"node_modules/./foo", true},
	}
	for _, tt := range tests {
		got := sanitize.HasTraversal(tt.path)
		if got != tt.want {
			t.Errorf("HasTraversal(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
