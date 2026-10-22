package naming

import (
	"strings"
	"testing"
)

func TestAppliedProjectKeyBounds(t *testing.T) {
	for _, key := range []string{"shop", "project-" + strings.Repeat("a", 48), strings.Repeat("a", 63)} {
		if !ValidProjectKey(key) {
			t.Errorf("valid applied project key rejected: %q", key)
		}
	}
	for _, key := range []string{"", "1shop", "Shop", "shop/name", "shop_name", "shop\n", strings.Repeat("a", 64), "shopé"} {
		if ValidProjectKey(key) {
			t.Errorf("invalid applied project key accepted: %q", key)
		}
	}
}
