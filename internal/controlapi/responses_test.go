package controlapi

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestCertificateIssuanceResponseWithholdsCertificateUntilInstallable(t *testing.T) {
	notBefore := time.Date(2026, 9, 15, 22, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(24 * time.Hour)
	for _, test := range []struct {
		state       string
		wantExposed bool
	}{
		{state: "finalizing"},
		{state: "waiting_for_install", wantExposed: true},
		{state: "installed", wantExposed: true},
	} {
		t.Run(test.state, func(t *testing.T) {
			response := certificateIssuanceResponse(controlstate.CertificateIssuance{
				State: test.state, CertificatePEM: "certificate", NotBefore: &notBefore, NotAfter: &notAfter,
			})
			if exposed := response.CertificatePem != nil || response.NotBefore != nil || response.NotAfter != nil; exposed != test.wantExposed {
				t.Fatalf("certificate material exposed = %v, want %v", exposed, test.wantExposed)
			}
		})
	}
}
