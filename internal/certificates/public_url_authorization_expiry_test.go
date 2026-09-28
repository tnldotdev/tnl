package certificates

import (
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestPublicURLWorkerCleansExpiredDNSChallengeWhenOrderFetchIsUnavailable(t *testing.T) {
	start := time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC)
	api, work := dnsSafetyOrder(t, "presented", start)
	api.getOrderErr = &acmeclient.Error{Status: http.StatusServiceUnavailable, Type: "urn:ietf:params:acme:error:serverInternal"}
	store := &certificateStoreStub{work: work}
	now := work.Authorizations[0].ExpiresAt.Add(time.Second)
	worker := &PublicURLWorker{
		store: store, config: PublicURLConfig{DNSChallenges: &dnsChallengesStub{}, PollInterval: time.Second},
		now:    func() time.Time { return now },
		client: func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil },
	}
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("process expired DNS authorization: found=%t error=%v", found, err)
	}
	if store.saved.State != "failed" || store.saved.Authorizations[0].State != "cleaning" {
		t.Fatalf("expired DNS challenge remains active after CA outage: state=%q authorization=%q error=%q", store.saved.State, store.saved.Authorizations[0].State, store.saved.LastError)
	}
	store.work = store.saved
	now = now.Add(time.Minute)
	if found, err := worker.processOne(t.Context()); !found || err != nil {
		t.Fatalf("process expired DNS cleanup: found=%t error=%v", found, err)
	}
	if store.saved.Authorizations[0].State != "complete" {
		t.Fatalf("expired DNS authorization was not cleaned: state=%q", store.saved.Authorizations[0].State)
	}
}
