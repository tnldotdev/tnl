package httpaccess

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestTemporaryBlocksUsePolicyRefreshAndExpireDuringOutage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
		var mode atomic.Int32
		until := time.Now().Add(time.Minute)
		client := policyClientFunc(func(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
			if mode.Load() == 1 {
				return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
			}
			update, err := base.ReadPublisherVisitorPolicy(ctx, request, token)
			if mode.Load() != 2 {
				update.TemporaryBlocks = []httpprotection.TemporaryBlock{{SourceIP: "192.0.2.1", ExpiresAt: until}}
			}
			return update, err
		})
		p, err := PreparePolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: visitorfixture.PublicURLID}, "run", 1, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		source := netip.MustParseAddr("192.0.2.1")
		calls := base.Calls.Load()
		for range 100 {
			if !p.SourceBlocked(source, time.Now()) || p.SourceBlocked(netip.MustParseAddr("192.0.2.2"), time.Now()) {
				t.Fatal("local snapshot lost its exact source")
			}
		}
		if base.Calls.Load() != calls {
			t.Fatal("request-time source lookup contacted control")
		}
		mode.Store(2)
		if err := p.Refresh(t.Context()); err != nil || p.SourceBlocked(source, time.Now()) {
			t.Fatal("disabled snapshot did not clear enforcement", err)
		}
		mode.Store(0)
		if err := p.Refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		mode.Store(1)
		time.Sleep(time.Minute)
		synctest.Wait()
		if p.SourceBlocked(source, time.Now()) {
			t.Fatal("control outage extended a temporary block")
		}
	})
}
