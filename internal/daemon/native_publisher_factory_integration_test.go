package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// exercise the installed SDKs and CLI at the private owner boundary. control
// checks signed requests, but deliberately assigns no service or relay.
func TestIntegrationNativePublisherFactory(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	testutil.UseClientKeychain(t)
	repo, directory := integrationRepositoryRoot(t), t.TempDir()
	binary := filepath.Join(directory, "tnl")
	buildIntegrationBinary(t, repo, binary, "./cmd/tnl")
	installPublicationSDKs(t, repo, directory, binary)

	member := controlv1.DeploymentPublisherIdentity{
		TeamId: "team", ProjectKey: "example", DeploymentName: "production",
		DeploymentId: "dpl_" + strings.Repeat("d", 22), PublisherIdentityId: "pub_" + strings.Repeat("p", 22),
		KeyId: "pkey_" + strings.Repeat("k", 22),
	}
	var mu sync.Mutex
	var admitted ed25519.PublicKey
	var bootstrap string
	var redeems, verifies, assignments int
	const lease = "fixture-publisher-lease"
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		reply := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(value)
		}
		switch r.URL.Path {
		case "/v1/publisher/deployments/enroll":
			var body controlv1.RedeemDeploymentPublisherEnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.EnrollmentKey != bootstrap || admitted != nil {
				t.Error("unexpected publisher admission")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			key, err := base64.RawURLEncoding.DecodeString(body.PublicKey)
			if err != nil || len(key) != ed25519.PublicKeySize {
				t.Error("enrollment sent an invalid publisher key")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			admitted = key
			redeems++
			reply(member)
		case "/v1/publisher/deployments/verify", "/v1/publisher/deployments/lease":
			var body controlv1.DeploymentPublisherLeaseRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
				body.PublisherIdentityId != member.PublisherIdentityId || body.DeploymentId != member.DeploymentId {
				t.Error("publisher selected a different deployment or identity")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if _, err := publisherproof.Verify(body.Assertion, member.PublisherIdentityId, member.KeyId, member.DeploymentId, "http://"+r.Host+r.URL.Path, admitted, time.Now()); err != nil {
				t.Error("publisher did not prove its enrolled key", err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/verify") {
				verifies++
				reply(controlv1.DeploymentPublisherVerification{Member: member, DeploymentNames: []string{"production"}})
			} else {
				reply(controlv1.DeploymentPublisherLease{AccessToken: lease, ExpiresAt: time.Now().Add(time.Minute)})
			}
		case "/v1/publisher/deployments/assignments":
			if r.URL.Query().Get("app_owned") != "true" || r.Header.Get("Authorization") != "Bearer "+lease {
				t.Error("publisher did not select app-owned assignments with its lease")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			assignments++
			reply(controlv1.DeploymentPublisherAssignments{Member: member, Revision: 1, ConfigurationHash: strings.Repeat("a", 64), Services: []controlv1.DeploymentPublisherServiceAssignment{}})
		default:
			t.Error("unexpected control operation", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer control.Close()

	for _, sdk := range []string{"node", "bun", "python"} {
		t.Run(sdk, func(t *testing.T) {
			key := "pen_" + strings.Repeat("e", 22) + "." + sdk
			mu.Lock()
			bootstrap, admitted = key, nil
			redeems, verifies, assignments = 0, 0, 0
			mu.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), 80*time.Second)
			defer cancel()
			var command *exec.Cmd
			if sdk == "python" {
				command = exec.CommandContext(ctx, "uv", "run", "--frozen", "--project", filepath.Join(repo, "packages/py"), "python", filepath.Join(directory, "enrolled-publisher.py"), control.URL)
			} else {
				command = exec.CommandContext(ctx, sdk, filepath.Join(directory, "enrolled-publisher.ts"), control.URL, sdk)
			}
			command.Dir = directory
			command.Stdin = strings.NewReader(key + "\n")
			command.Env = append(os.Environ(), "TNL_STATE_DIR="+filepath.Join(directory, "state-"+sdk), "TNL_NO_TELEMETRY=1", "PYTHONPATH="+filepath.Join(directory, "python"))
			stop := isolateIntegrationCommand(t, command)
			defer stop()
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("%s SDK did not open, fence, close, and reopen its publisher: %v\n%s", sdk, err, output)
			}
			mu.Lock()
			defer mu.Unlock()
			if redeems != 1 || verifies != 2 || assignments != 1 {
				t.Fatal("SDK did not verify on each open and fence publication against assignments", redeems, verifies, assignments)
			}
		})
	}
}
