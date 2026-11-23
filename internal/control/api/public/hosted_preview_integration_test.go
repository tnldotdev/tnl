package public

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestIntegrationMemberHostedPreviewPublicationAndResume(t *testing.T) {
	f := newCompanyHTTPFixture(t, "member_hosted_preview")
	clientstate.UseMemoryKeychainForTesting()
	team, _, session := newMemberPublicationFixture(t, f)
	const domain = "example.test"
	h, err := NewHandler(Config{
		ControlURL: f.server.URL, ManagedDomain: domain, ManagedURLMode: naming.ManagedURLModeGenerated,
		OIDCIssuer: f.issuer.URL, DNSAutomation: true, CertificateIssuance: true,
		ACMEDirectoryURL: "https://ca.example.test/directory",
	}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mux.Handle("/", h)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(target.Close)
	member, err := clientcontrol.New(f.server.URL, f.server.Client(), credentials.AccessToken(session.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	firstState := filepath.Join(t.TempDir(), "state")
	projectRoot := t.TempDir()
	stop := errors.New("stop after signed run preparation")
	type publication struct {
		address, publisher, service string
		number                      uint64
		names                       []string
	}
	publish := func(state, savedAddress string, ephemeral bool) publication {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		var run publication
		var resume string
		err := invocation.PublishHTTP(ctx, invocation.PublicOptions{
			Target: target.URL, StateDir: state, SelectedTeam: team.ID, ServerURL: f.server.URL, ProjectRoot: projectRoot,
			AccessToken: session.AccessToken, PublicURL: savedAddress, Ephemeral: ephemeral, FallbackName: "readable-worktree",
			Authenticate: func(ctx context.Context, db *clientstate.Database, server, token string) (*auth.Client, error) {
				return auth.Authenticate(ctx, auth.Config{ServerEndpoint: server, State: db, AccessToken: token, HTTPClient: f.server.Client()})
			},
		}, &invocation.Presentation{
			Resume: func(url, teamID, server string) error {
				if teamID != team.ID || server != f.server.URL {
					return errors.New("resume offered another team or server")
				}
				resume = url
				return nil
			},
			Provisioning: func(url string, number uint64) error {
				run.address, run.number = url, number
				return stop
			},
		})
		if !errors.Is(err, stop) || run.address == "" {
			t.Fatalf("publication did not reach signed run preparation: %v", err)
		}
		if (!ephemeral && savedAddress == "" && resume != run.address) ||
			((ephemeral || savedAddress != "") && resume != "") {
			t.Fatalf("wrong resume address %q for %q", resume, run.address)
		}
		var closed, deleted bool
		err = f.sql.QueryRow(t.Context(), `SELECT r.service_id,r.publisher_identity_id,r.certificate_identifiers,r.closed_at IS NOT NULL,s.deleted_at IS NOT NULL
		    FROM control.service_runs r JOIN control.services s ON s.id=r.service_id
		    WHERE r.team_id=$1 AND r.certificate_hostname=$2 AND r.run_number=$3`,
			team.ID, strings.TrimPrefix(run.address, "https://"), run.number).Scan(&run.service, &run.publisher, &run.names, &closed, &deleted)
		if err != nil || !closed || deleted != ephemeral {
			t.Fatalf("publication cleanup: closed=%t deleted=%t: %v", closed, deleted, err)
		}
		return run
	}

	first := publish(firstState, "", false)
	hostname := strings.TrimPrefix(first.address, "https://")
	parent, ok := naming.PreviewHostname(hostname, domain)
	if !ok || !slices.Equal(first.names, []string{"*." + parent}) {
		t.Fatalf("unnamed publication did not use its opaque parent: %q %v", first.address, first.names)
	}
	resumed := publish(firstState, first.address, false)
	if resumed.address != first.address || resumed.service != first.service || resumed.publisher != first.publisher ||
		resumed.number <= first.number || !slices.Equal(resumed.names, first.names) {
		t.Fatalf("resume did not reuse the saved address and publisher: %+v", resumed)
	}
	replacement := publish(filepath.Join(t.TempDir(), "state"), first.address, false)
	if replacement.address != first.address || replacement.service != first.service || replacement.publisher == first.publisher ||
		!slices.Equal(replacement.names, []string{hostname}) {
		t.Fatalf("replacement did not get exact-host authority: %+v", replacement)
	}
	temporary := publish(firstState, "", true)
	temporaryHost := strings.TrimPrefix(temporary.address, "https://")
	if temporary.address == first.address || temporary.publisher != first.publisher || !slices.Equal(temporary.names, first.names) {
		t.Fatalf("ephemeral publication did not allocate another address under the same parent: %+v", temporary)
	}
	if _, err := member.GetServiceByHostname(t.Context(), team.ID, temporaryHost); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("stopped ephemeral address is still selectable: %v", err)
	}
}
