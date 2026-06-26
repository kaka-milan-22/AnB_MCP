package tools

import "testing"

// safeOutPath must confine an agent-supplied relative path to the render base
// dir — rejecting absolute paths and any traversal that escapes the base.
func TestSafeOutPath(t *testing.T) {
	base := "/render"

	ok := []struct {
		rel  string
		want string
	}{
		{"app/config.yaml", "/render/app/config.yaml"},
		{"x.env", "/render/x.env"},
		{"a/../b.txt", "/render/b.txt"}, // normalizes but stays inside
	}
	for _, c := range ok {
		got, err := safeOutPath(base, c.rel)
		if err != nil {
			t.Errorf("safeOutPath(%q,%q) unexpected err: %v", base, c.rel, err)
			continue
		}
		if got != c.want {
			t.Errorf("safeOutPath(%q,%q) = %q, want %q", base, c.rel, got, c.want)
		}
	}

	bad := []string{
		"/etc/passwd",       // absolute
		"../etc/passwd",     // escapes base
		"a/../../etc/x",     // escapes via traversal
		"",                  // empty
	}
	for _, rel := range bad {
		if _, err := safeOutPath(base, rel); err == nil {
			t.Errorf("safeOutPath(%q,%q) should have errored", base, rel)
		}
	}
}
