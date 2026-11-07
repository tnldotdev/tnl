package local

import (
	"strings"
	"testing"
)

func TestAppProxyTokenRequiresExactPrivateCredential(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 65)} {
		if validProxyToken(value) {
			t.Fatalf("accepted invalid app proxy token of length %d", len(value))
		}
	}
	if !validProxyToken(strings.Repeat("a", 64)) {
		t.Fatal("rejected app proxy token")
	}
}
