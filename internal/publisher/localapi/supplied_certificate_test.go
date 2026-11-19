package localapi

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	localv1 "github.com/tnldotdev/tnl/pkg/api/publisher/local/v1"
)

func TestSuppliedCertificateRenewalRequiresExactInvocationOwner(t *testing.T) {
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	const invocation = "ivk_0123456789abcdefghijkl"
	const owner = "0123456789abcdef0123456789abcdef"
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := publisherapp.New(t.Context(), root, database, []publisherapp.Service{{Name: invocation}}, func(ctx context.Context, _ publisherapp.Service, _ func(publisherapp.PublicationUpdate) error) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve(invocation, owner, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	const target = "http://127.0.0.1:3000"
	if err := manager.Register(id, owner, target, "node"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	caps, err := publisherprotocol.NewCapabilities("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	name := invocation
	endpoint, err := caps.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &name})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server.Config.Handler = (&Server{Capabilities: caps, Manager: manager, RenewCertificate: func(request publisherprotocol.Registration) error {
		calls.Add(1)
		if request.RegistrationID != id || request.Owner != owner || request.Target != target {
			t.Error("replacement crossed registration ownership")
		}
		return nil
	}}).Handler()
	server.Start()
	defer server.Close()
	request := publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: owner, Target: target,
		Certificate: &localv1.SuppliedServiceCertificateMaterial{CertificatePem: "chain", PrivateKeyPem: "private-key"}}
	wrong := request
	wrong.Owner = "ffffffffffffffffffffffffffffffff"
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/renew", wrong, nil); err == nil || calls.Load() != 0 {
		t.Fatal("another owner replaced certificate material", err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/register", request, nil); err == nil || calls.Load() != 0 {
		t.Fatal("app registration accepted invocation replacement material", err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/renew", request, nil); err != nil || calls.Load() != 1 {
		t.Fatal("exact invocation could not replace material", err)
	}
	if err := publisherprotocol.Call(t.Context(), caps.Owner(), "POST", "/v1/renew", request, nil); err == nil || calls.Load() != 1 {
		t.Fatal("owner capability bypassed invocation-only replacement", err)
	}
}
