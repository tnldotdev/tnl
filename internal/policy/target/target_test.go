package target

import (
	"strings"
	"testing"
)

func TestValidMountPrefix(t *testing.T) {
	for _, prefix := range []string{"/api", "/api/v1", "/a_b.~-/C1", "/" + strings.Repeat("a", 255)} {
		if !ValidMountPrefix(prefix) {
			t.Fatalf("rejected %q", prefix)
		}
	}
	for _, prefix := range []string{"", "/", "api", "/api/", "//api", "/api//v1", "/.", "/..", "/a/../b", "/a%2fb", "/api?q=1", "/a#b", "/a\\b", "/a b", "/__tnl", "/__tnl/feedback", "/" + strings.Repeat("a", 256)} {
		if ValidMountPrefix(prefix) {
			t.Fatalf("accepted %q", prefix)
		}
	}
}
