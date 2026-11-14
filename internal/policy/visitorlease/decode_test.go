package visitorlease

import (
	"errors"
	"strings"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDecodePortBoundsPreserveResourceKind(t *testing.T) {
	for _, kind := range []controlv1.VisitorResourceScopeKind{"public_url", "service"} {
		id := "url_" + strings.Repeat("A", 22)
		if kind == "service" {
			id = "svc_" + strings.Repeat("A", 22)
		}
		for _, port := range []int{-1, 0, 443, 25443, 65535, 65536} {
			update, err := Decode(controlv1.VisitorPolicyUpdate{Policy: controlv1.VisitorPolicySnapshot{
				Resource: controlv1.VisitorResourceScope{Kind: kind, Id: id}, Port: port,
			}})
			valid := port >= 0 && port <= 65535 && (port != 0 || kind == "service")
			if valid {
				if err != nil || int(update.View.Port) != port || string(update.View.Scope.Kind) != string(kind) {
					t.Fatal("wire policy lost its exact endpoint", kind, port, err)
				}
			} else if !errors.Is(err, ErrUpdate) {
				t.Fatal("invalid port reached narrowed policy", kind, port, err)
			}
		}
	}
}
