package stream

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func adapterFixture(t *testing.T, identity string, handler func(*clientstate.Store, http.ResponseWriter, *http.Request)) (Control, *clientstate.Store) {
	t.Helper()
	var profile *clientstate.Store
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer signed-in-visitor" {
			t.Error("connector did not use the signed-in visitor")
		}
		w.Header().Set("Content-Type", "application/json")
		handler(profile, w, r)
	}))
	t.Cleanup(server.Close)
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	profile, err = state.Server(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientcontrol.New(server.URL, server.Client(), "signed-in-visitor")
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewControl(client, profile, identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := control.(interface{ Close() error }).Close(); err != nil {
			t.Error(err)
		}
	})
	return control, profile
}

func TestControlDevicePersistsRetryKeyAndRejectsChangedEnrollment(t *testing.T) {
	for _, bad := range []string{"lost-response", "identity", "key", "id", "revoked"} {
		t.Run(bad, func(t *testing.T) {
			identity, id := connectorID(t, opaqueid.IdentityPrefix), connectorID(t, "vdev_")
			var public string
			calls := 0
			control, state := adapterFixture(t, identity, func(profile *clientstate.Store, w http.ResponseWriter, r *http.Request) {
				calls++
				var body controlv1.EnrollVisitorDeviceJSONRequestBody
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				stored, found, err := profile.VisitorDevice(r.Context(), identity)
				if err != nil || !found || stored.ID != "" || hex.EncodeToString(stored.PublicKey) != body.PublicKey {
					t.Error("enrollment was sent before persisting the exact protected key")
				}
				if public != "" && public != body.PublicKey {
					t.Error("retry changed the device key")
				}
				public = body.PublicKey
				result := controlv1.VisitorDevice{Id: id, IdentityId: identity, PublicKey: public, CreatedAt: time.Now()}
				if calls == 1 {
					switch bad {
					case "lost-response":
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = w.Write([]byte(`{}`))
						return
					case "identity":
						result.IdentityId = connectorID(t, opaqueid.IdentityPrefix)
					case "key":
						result.PublicKey = strings.Repeat("00", ed25519.PublicKeySize)
					case "id":
						result.Id = "unvalidated"
					case "revoked":
						now := time.Now()
						result.RevokedAt = &now
					}
				}
				_ = json.NewEncoder(w).Encode(result)
			})
			if _, err := control.ConnectorSigner(t.Context(), identity); err == nil {
				t.Fatal("invalid enrollment accepted")
			}
			stored, found, err := state.VisitorDevice(t.Context(), identity)
			if err != nil || !found || stored.ID != "" {
				t.Fatal("failed enrollment replaced or enrolled the protected key")
			}
			device, err := control.ConnectorSigner(t.Context(), identity)
			if err != nil || device.Subject.DeviceID != id || !bytes.Equal(device.PublicKey, stored.SigningKey.Public().(ed25519.PublicKey)) || !ed25519.Verify(device.PublicKey, []byte("proof"), device.Sign([]byte("proof"))) {
				t.Fatal("retry did not enroll the original key")
			}
			if _, err := control.ConnectorSigner(t.Context(), identity); err != nil || calls != 2 {
				t.Fatal("enrolled device was unnecessarily enrolled again")
			}
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if strings.Contains(fmt.Sprintf(format, device), hex.EncodeToString(stored.SigningKey)) || fmt.Sprintf(format, device) != "private connector signer" {
					t.Fatal("device formatting disclosed protected state")
				}
			}
		})
	}
}

func TestControlAssignmentFailureConsumesOnlyRequestedSlot(t *testing.T) {
	identity, device, service := connectorID(t, opaqueid.IdentityPrefix), connectorID(t, "vdev_"), connectorID(t, opaqueid.ServicePrefix)
	var pairs [][2]string
	var singles []string
	var excluded []string
	var attempted []string
	released := make(map[string]bool)
	control, _ := adapterFixture(t, identity, func(_ *clientstate.Store, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/visitor-devices":
			var body controlv1.EnrollVisitorDeviceJSONRequestBody
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(controlv1.VisitorDevice{Id: device, IdentityId: identity, PublicKey: body.PublicKey, CreatedAt: time.Now()})
		case strings.HasSuffix(r.URL.Path, "/ingress-assignments"):
			ids := [2]string{connectorID(t, opaqueid.ConnectorSessionPrefix), connectorID(t, opaqueid.ConnectorSessionPrefix)}
			pairs = append(pairs, ids)
			setups := []controlv1.ConnectorSessionSetup{}
			for i, id := range ids {
				setups = append(setups, controlv1.ConnectorSessionSetup{ConnectorSessionId: id, Subject: visitorsubject.Wire(tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device, IdentityID: identity}), ServiceId: service,
					IngressId: []string{"a", "b"}[i], IngressAddress: "127.0.0.1:443", TlsServerName: "ingress.example", SessionCredential: "one-use", ExpiresAt: time.Now().Add(time.Minute)})
			}
			// control response order is not a stable connection slot.
			setups[0], setups[1] = setups[1], setups[0]
			_ = json.NewEncoder(w).Encode(setups)
		case strings.HasSuffix(r.URL.Path, "/ingress-assignment"):
			var body controlv1.CreateVisitorIngressAssignmentJSONRequestBody
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DeviceId != device {
				t.Error("single-slot refresh changed the device", err)
			}
			exclude := ""
			if body.ExcludeIngressId != nil {
				exclude = *body.ExcludeIngressId
			}
			excluded = append(excluded, exclude)
			ingress := "a"
			if ingress == exclude {
				ingress = "b"
			}
			id := connectorID(t, opaqueid.ConnectorSessionPrefix)
			singles = append(singles, id)
			_ = json.NewEncoder(w).Encode(controlv1.ConnectorSessionSetup{ConnectorSessionId: id, Subject: visitorsubject.Wire(tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device, IdentityID: identity}), ServiceId: service,
				IngressId: ingress, IngressAddress: "127.0.0.1:443", TlsServerName: "ingress.example", SessionCredential: "one-use", ExpiresAt: time.Now().Add(time.Minute)})
		case strings.HasSuffix(r.URL.Path, "/transport-trust"):
			parts := strings.Split(r.URL.Path, "/")
			attempted = append(attempted, parts[len(parts)-2])
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete:
			parts := strings.Split(r.URL.Path, "/")
			released[parts[len(parts)-1]] = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected adapter operation %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	for _, slot := range []uint8{0, 0, 1, 1} {
		if _, err := control.ConnectorAssignment(t.Context(), service, tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device, IdentityID: identity}, slot); err == nil {
			t.Fatal("missing transport trust used default roots")
		}
	}
	if len(pairs) != 1 || len(singles) != 2 || len(attempted) != 4 || attempted[0] != pairs[0][0] || attempted[1] != singles[0] || attempted[2] != pairs[0][1] || attempted[3] != singles[1] || excluded[0] != "b" {
		t.Fatalf("slot retry consumed a sibling or reused a token: pairs=%v singles=%v attempts=%v excluded=%v", pairs, singles, attempted, excluded)
	}
	var workers sync.WaitGroup
	for range 4 {
		for slot := range uint8(2) {
			workers.Go(func() {
				if _, err := control.ConnectorAssignment(t.Context(), service, tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device, IdentityID: identity}, slot); err == nil {
					t.Error("failed trust lookup returned an assignment")
				}
			})
		}
	}
	workers.Wait()
	seen := make(map[string]bool)
	for _, id := range attempted {
		if seen[id] {
			t.Fatal("concurrent slot recovery reused a token")
		}
		seen[id] = true
		if !released[id] {
			t.Fatal("failed trust lookup left a reservation")
		}
	}
	if err := control.(interface{ Close() error }).Close(); err != nil {
		t.Fatal(err)
	}
	for _, pair := range pairs {
		for _, id := range pair {
			if !released[id] {
				t.Fatal("shutdown left an unused sibling reserved")
			}
		}
	}
	if len(pairs) != 1 {
		t.Fatal("slot refresh allocated another startup pair")
	}
	for _, id := range singles {
		if !released[id] {
			t.Fatal("shutdown left a single-slot reservation")
		}
	}
}

func TestControlSelectionBindsDeviceServiceProtocolAndRevision(t *testing.T) {
	identity, device, service := connectorID(t, opaqueid.IdentityPrefix), connectorID(t, "vdev_"), connectorID(t, opaqueid.ServicePrefix)
	selected := controlv1.ServiceSelection{Subject: visitorsubject.Wire(tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device, IdentityID: identity}), ServiceId: service, ServiceRunId: connectorID(t, opaqueid.ServiceRunPrefix),
		Protocol: controlv1.ServiceProtocol("http"), TrustRevision: 4, RunNumber: 9, Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test", Port: 25443}, ExpiresAt: time.Now().Add(time.Minute)}
	var mu sync.Mutex
	control, _ := adapterFixture(t, identity, func(_ *clientstate.Store, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/visitor-devices" {
			var body controlv1.EnrollVisitorDeviceJSONRequestBody
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(controlv1.VisitorDevice{Id: device, IdentityId: identity, PublicKey: body.PublicKey, CreatedAt: time.Now()})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/v1/visitor-tokens" {
			var request controlv1.VisitorTokenRequest
			var source controlv1.VisitorTokenDeviceSource
			if json.NewDecoder(r.Body).Decode(&request) != nil || json.Unmarshal(request.Source, &source) != nil || source.Kind != controlv1.VisitorTokenDevice || source.DeviceId != device || request.Resource.Kind != "service" || request.Resource.Id != service {
				t.Error("native permission lost its exact service/device source")
			}
			_ = json.NewEncoder(w).Encode(fixtureVisitorPermission(Run{ServiceID: service, Endpoint: selected.Endpoint}))
			return
		}
		_ = json.NewEncoder(w).Encode(selected)
	})
	run, err := control.ResolveService(t.Context(), service)
	if err != nil || run.TrustRevision != 4 || run.Protocol != "http" || run.Endpoint == nil || run.Endpoint.Hostname != selected.Endpoint.Hostname {
		t.Fatalf("selected metadata changed: %+v %v", run, err)
	}
	mu.Lock()
	selected.Subject.DeviceId = new(connectorID(t, "vdev_"))
	mu.Unlock()
	if _, err := control.ResolveService(t.Context(), service); err == nil {
		t.Fatal("selection for another device accepted")
	}
}
