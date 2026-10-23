package public

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVisitorTokenSourceRejectsMixedUnknownAndIncompleteVariants(t *testing.T) {
	for _, source := range []string{
		`null`, `[]`, `{}`, `{"kind":"publisher"}`,
		`{"kind":"control_session","secret":"ignored"}`,
		`{"kind":"control_session","preview_id":"bad"}`,
		`{"kind":"device"}`,
		`{"kind":"device","device_id":"vdev_` + strings.Repeat("A", 22) + `","credential":"ignored"}`,
		`{"kind":"workload"}`,
		`{"kind":"share","share_id":"shr_` + strings.Repeat("A", 22) + `"}`,
		`{"kind":"browser_session","secret":"` + strings.Repeat("A", 43) + `","identity_id":"ignored"}`,
		`{"kind":"grant","credential":"` + strings.Repeat("A", 129) + `"}`,
	} {
		if _, _, err := parseVisitorTokenSource(json.RawMessage(source)); err == nil {
			t.Fatal("accepted an ambiguous visitor source")
		}
	}
	for source, human := range map[string]bool{
		`{"kind":"control_session"}`: true,
		`{"kind":"device","device_id":"vdev_` + strings.Repeat("A", 22) + `"}`:                                         true,
		`{"kind":"browser_session","secret":"` + strings.Repeat("A", 43) + `"}`:                                        false,
		`{"kind":"workload","credential":"wlc_` + strings.Repeat("A", 43) + `"}`:                                       false,
		`{"kind":"share","share_id":"shr_` + strings.Repeat("A", 22) + `","secret":"` + strings.Repeat("B", 43) + `"}`: false,
	} {
		parsed, needsHuman, err := parseVisitorTokenSource(json.RawMessage(source))
		if err != nil || parsed == nil || needsHuman != human {
			t.Fatal("incorrect source authentication boundary", err)
		}
	}
}
