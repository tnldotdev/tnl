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
		state       controlstate.ACMEOrderState
		wantExposed bool
	}{
		{state: controlstate.ACMEOrderFinalizing},
		{state: controlstate.ACMEOrderWaitingForInstall, wantExposed: true},
		{state: controlstate.ACMEOrderInstalled, wantExposed: true},
	} {
		t.Run(string(test.state), func(t *testing.T) {
			response := certificateIssuanceResponse(controlstate.CertificateIssuance{
				State: test.state, CertificatePEM: "certificate", NotBefore: &notBefore, NotAfter: &notAfter,
			})
			if test.wantExposed {
				if response.CertificatePem == nil || *response.CertificatePem != "certificate" ||
					response.NotBefore == nil || !response.NotBefore.Equal(notBefore) ||
					response.NotAfter == nil || !response.NotAfter.Equal(notAfter) {
					t.Fatalf("installable certificate = %#v", response)
				}
			} else if response.CertificatePem != nil || response.NotBefore != nil || response.NotAfter != nil {
				t.Fatalf("certificate material exposed before installable: %#v", response)
			}
		})
	}
}
