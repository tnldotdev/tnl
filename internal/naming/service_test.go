package naming

import (
	"strings"
	"testing"
)

func TestValidServiceName(t *testing.T) {
	for _, value := range []string{"a", "api", "api-2", "a--b", strings.Repeat("a", 32)} {
		if !ValidServiceName(value) {
			t.Errorf("rejected %q", value)
		}
	}
	for _, value := range []string{"", "2api", "API", "-api", "api-", "a.b", "a_b", "api ", "a\tb", "\u00e9", strings.Repeat("a", 33)} {
		if ValidServiceName(value) {
			t.Errorf("accepted %q", value)
		}
	}
}
