package certificates

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRetiredIssuanceRecoversUncertainCertificateLifetime(t *testing.T) {
	now := time.Now().UTC()
	for _, state := range []controlstate.ACMEOrderState{controlstate.ACMEOrderFailed, controlstate.ACMEOrderCanceled} {
		t.Run(string(state), func(t *testing.T) {
			api, work := dnsSafetyOrder(t, "finalizing", now)
			api.certificatePEM = work.CertificatePEM
			api.order.Status, api.order.Certificate = "valid", "https://acme.example.test/certificate/1"
			work.State, work.FinalizationPossible = state, true
			work.CertificatePEM, work.NotBefore, work.NotAfter, work.RenewAt = nil, nil, nil, nil
			worker := &PublicURLWorker{config: PublicURLConfig{DNSChallenges: &dnsChallengesStub{}}}
			if err := worker.advance(t.Context(), api, &work, now); err != nil || work.NotAfter == nil || !work.NotAfter.After(now) || work.State != controlstate.ACMEOrderWaitingForInstall || len(api.finalizations) != 0 {
				t.Fatal("retirement lost an issued certificate's real lifetime", work, err)
			}
			work.State, work.CertificatePEM, work.NotBefore, work.NotAfter = state, nil, nil, nil
			api.order.Status, api.order.Certificate = "invalid", ""
			if err := worker.advance(t.Context(), api, &work, now); err == nil || work.FinalizationPossible {
				t.Fatal("a confirmed invalid order stayed uncertain forever", work, err)
			}
		})
	}
}
