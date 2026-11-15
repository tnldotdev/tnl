package benchworkload

import (
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
)

func TestMeasurementResponseIncludesOnlyKnownDiagnosticCodes(t *testing.T) {
	for _, code := range []diagnostic.Code{"", diagnostic.HttpProtectionUnavailable, "secret request data"} {
		err := &measurementResponseError{operation: "unverified visitor response", status: 503, code: code}
		message := safeMeasurementFailure(err)
		if !strings.Contains(message, "status 503") || strings.Contains(message, "secret request data") {
			t.Fatal(message)
		}
		if strings.Contains(message, string(diagnostic.HttpProtectionUnavailable)) != (code == diagnostic.HttpProtectionUnavailable) {
			t.Fatal("known diagnostic missing or unknown value accepted", message)
		}
	}
}
