package local

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestSDKPublisherRecoversThroughPrivatePipeAndReleasesSlotOnEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	instance := "replica"
	root := filepath.Join(t.TempDir(), "state")
	options := Options{Directory: t.TempDir(), StateDir: root}
	member := controlv1.DeploymentPublisherIdentity{
		TeamId: "team", ProjectKey: "example", DeploymentName: "production",
		DeploymentId: "dpl_" + strings.Repeat("d", 22), PublisherIdentityId: "pub_" + strings.Repeat("p", 22),
		KeyId: "pkey_" + strings.Repeat("k", 22),
	}
	bootstrap := "pen_" + strings.Repeat("e", 22) + ".first-enrollment"
	var mu sync.Mutex
	var admitted ed25519.PublicKey
	redeems, verifies := 0, 0
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/publisher/deployments/enroll":
			var body controlv1.RedeemDeploymentPublisherEnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.EnrollmentKey != bootstrap ||
				body.DeploymentId != nil || body.ProjectKey != nil {
				t.Error("enrollment did not use bootstrap-derived scope")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			public, err := base64.RawURLEncoding.DecodeString(body.PublicKey)
			if err != nil || len(public) != ed25519.PublicKeySize || admitted != nil && !bytes.Equal(admitted, public) {
				t.Error("recovery did not use the durable signing key")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			redeems++
			admitted = public
			if redeems == 1 {
				state, err := os.ReadFile(filepath.Join(root, "sdk-publisher-"+instance+".sealed"))
				if err != nil || len(state) == 0 || bytes.Contains(state, []byte(bootstrap)) {
					t.Error("bootstrap was sent before the key was protected", err)
				}
				// grant committed, but the client cannot read its result.
				_, _ = io.WriteString(w, "{")
				return
			}
			_ = json.NewEncoder(w).Encode(member)
		case "/v1/publisher/deployments/verify":
			var body controlv1.DeploymentPublisherLeaseRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
				body.PublisherIdentityId != member.PublisherIdentityId || body.DeploymentId != member.DeploymentId {
				t.Error("verification selected the wrong identity")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			origin := "http://" + r.Host
			if _, err := publisherproof.Verify(body.Assertion, member.PublisherIdentityId, member.KeyId, member.DeploymentId, origin+r.URL.Path, admitted, time.Now()); err != nil {
				t.Error("verification did not prove the enrolled key", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			verifies++
			_ = json.NewEncoder(w).Encode(controlv1.DeploymentPublisherVerification{Member: member, DeploymentNames: []string{"production"}})
		default:
			t.Error("unexpected control operation", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(control.Close)

	open := func(server string) (*io.PipeWriter, *json.Decoder, <-chan error) {
		t.Helper()
		input, send := io.Pipe()
		receive, output := io.Pipe()
		done := make(chan error, 1)
		go func() {
			defer output.Close()
			done <- ServeSDKPublisher(ctx, options, instance, server, input, output)
		}()
		t.Cleanup(func() {
			_ = send.Close()
			_ = receive.Close()
		})
		stop := context.AfterFunc(ctx, func() {
			_ = send.Close()
			_ = receive.Close()
		})
		t.Cleanup(func() { stop() })
		return send, json.NewDecoder(bufio.NewReader(receive)), done
	}
	sendBootstrap := func(send *io.PipeWriter, pipe *json.Decoder, key string) {
		t.Helper()
		var challenge struct{ Type string }
		if err := pipe.Decode(&challenge); err != nil || challenge.Type != "enrollment" {
			t.Fatal("native owner did not ask for enrollment", err)
		}
		if err := json.NewEncoder(send).Encode(key); err != nil {
			t.Fatal(err)
		}
	}
	reject := func(send *io.PipeWriter, pipe *json.Decoder, done <-chan error) {
		t.Helper()
		if err := pipe.Decode(new(any)); !errors.Is(err, io.EOF) {
			t.Fatal("rejected startup produced an owner", err)
		}
		_ = send.Close()
		if err := <-done; err == nil {
			t.Fatal("rejected startup succeeded")
		}
	}
	ready := func(pipe *json.Decoder) sdkPublisherReady {
		t.Helper()
		var message sdkPublisherReady
		if err := pipe.Decode(&message); err != nil || message.Type != "ready" ||
			message.ControlURL != control.URL || message.Publisher != member.PublisherIdentityId ||
			message.Deployment != member.DeploymentId || message.Endpoint.Scope != "owner" ||
			publisherprotocol.ValidateEndpoint(message.Endpoint) != nil {
			t.Fatal("invalid ready message", err)
		}
		return message
	}
	closeOwner := func(send *io.PipeWriter, done <-chan error) {
		t.Helper()
		_ = send.Close()
		if err := <-done; err != nil {
			t.Fatal("native runtime did not join after pipe EOF", err)
		}
	}

	send, pipe, done := open(control.URL)
	sendBootstrap(send, pipe, bootstrap)
	reject(send, pipe, done)
	send, pipe, done = open("")
	sendBootstrap(send, pipe, bootstrap+"-wrong")
	reject(send, pipe, done)
	send, pipe, done = open("")
	sendBootstrap(send, pipe, bootstrap)
	first := ready(pipe)
	if !Available(ctx, first.Endpoint) {
		t.Fatal("the scoped endpoint was not available to the SDK")
	}
	entries, err := os.ReadDir(filepath.Join(root, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			t.Fatal("the SDK owner's capability was written to a discovery descriptor")
		}
	}
	closeOwner(send, done)
	if Available(ctx, first.Endpoint) {
		t.Fatal("the endpoint survived after the SDK's native owner joined")
	}

	send, pipe, done = open("http://127.0.0.1:1")
	reject(send, pipe, done)
	send, pipe, done = open("")
	second := ready(pipe)
	if first.Endpoint.OwnerId == second.Endpoint.OwnerId {
		t.Fatal("reopen reused the previous local app owner")
	}
	closeOwner(send, done)
	mu.Lock()
	defer mu.Unlock()
	if redeems != 2 || verifies != 2 {
		t.Fatal("reopen used extra enrollment or skipped verification", redeems, verifies)
	}
}
