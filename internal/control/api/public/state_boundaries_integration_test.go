package controlapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestIntegrationPrivateInventoryLargeTrust(t *testing.T) {
	f, owner, _, team, _ := serviceFixture(t)
	if _, err := f.sql.Exec(t.Context(), `UPDATE control.ingress_service_port_ranges SET last_port=20200`); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Value: bytes.Repeat([]byte{1}, 22<<10)}}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if len(bundle) < 30<<10 || len(bundle) > 32<<10 {
		t.Fatal("fixture must exercise a valid nearly-32-KiB CA bundle", len(bundle))
	}
	digest := sha256.Sum256([]byte("database.internal\x00pem\x00" + bundle))
	metadata := controlstate.PrivateServiceMetadata{Protocol: "postgres", TLS: &controlstate.PrivateServiceTLS{Hostname: "database.internal", PEM: bundle, Digest: hex.EncodeToString(digest[:])}}
	var exact string
	for i := range 101 {
		s, err := f.d.CreatePrivateService(t.Context(), team.ID, owner.Identity.Identity.Id, fmt.Sprintf("db-%03d", i), fmt.Sprintf("db-%03d", i), f.now, metadata)
		if err != nil {
			t.Fatal(err)
		}
		exact = s.ID
	}
	h, err := NewHandler(Config{}, f.d, f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	client, err := controlclient.New(server.URL, server.Client(), credentials.AccessToken(owner.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("management real bounded client", func(t *testing.T) {
		services, err := client.ListPrivateServices(t.Context(), team.ID)
		if err != nil || len(services) != 102 {
			t.Fatalf("management inventory with 101 valid CA bundles: count=%d err=%v", len(services), err)
		}
		for _, s := range services {
			if s.TargetTls != nil {
				t.Fatal("management inventory exposed publisher target trust")
			}
		}
	})
	t.Run("visitor real bounded client", func(t *testing.T) {
		services, err := client.ListAvailablePrivateServices(t.Context())
		if err != nil || len(services) != 102 {
			t.Fatalf("visitor inventory: count=%d err=%v", len(services), err)
		}
		for _, s := range services {
			if s.TargetTls != nil {
				t.Fatal("visitor inventory exposed publisher target trust")
			}
		}
	})
	t.Run("signed authority inventory", func(t *testing.T) {
		path := "/v1/service/teams/" + team.ID + "/private-services"
		w := f.serviceCall("GET", path, serviceOwnerSub, nil, nil)
		serviceResult(t, w, 200, nil)
		if w.Body.Len() >= 1<<20 || strings.Contains(w.Body.String(), `"target_tls"`) {
			t.Fatalf("authority inventory carries full publisher trust: %d bytes", w.Body.Len())
		}
	})
	full, err := client.GetPrivateService(t.Context(), exact)
	if err != nil || full.TargetTls == nil || full.TargetTls.Pem == nil || *full.TargetTls.Pem != bundle {
		t.Fatal("exact service lookup lost publisher trust", err)
	}
}

func TestIntegrationCompanyAdmissionPagination(t *testing.T) {
	f, _, recipient, team, _ := serviceFixture(t)
	var connection controlstate.IdentityConnectionSetup
	base := "/v1/service/teams/" + team.ID + "/identity-connections"
	f.decode(f.ownerCall("POST", base, serviceOwnerSub, nil, authorityv1.CreateIdentityConnectionRequest{Admission: authorityv1.CreateConnectionApproval, SourceId: "source"}), 201, &connection)
	// decided and old-source requests are history too. a busy history must not
	// hide later pending requests, including ties and mixed-case opaque IDs.
	if _, err := f.sql.Exec(t.Context(), `INSERT INTO control.company_admission_requests(id,team_id,identity_connection_id,connection_revision,identity_id,subject,member_slug,state,created_at)
		SELECT 'caq_' || (CASE WHEN n%2=0 THEN 'A' ELSE 'a' END) || lpad(n::text,21,'0'),$1,$2,n,$3,'directory-person','person',CASE WHEN n<=1000 THEN 'denied' ELSE 'pending' END,
		$4::timestamptz + CASE WHEN n<=1000 THEN interval '0 seconds' ELSE interval '1 second' END FROM generate_series(1,1002) n`, team.ID, connection.ID, recipient.Identity.Identity.Id, f.now); err != nil {
		t.Fatal(err)
	}
	path := "/v1/service/teams/" + team.ID + "/company-admissions"
	api, err := authorityv1.NewClientWithResponses(f.server.URL, authorityv1.WithHTTPClient(f.server.Client()), authorityv1.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+companyWebsiteSecret)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	var all []authorityv1.CompanyAdmissionRequest
	var cursor *string
	for range 20 {
		target := path
		if cursor != nil {
			target += "?cursor=" + *cursor
		}
		token := f.token(serviceOwnerSub, controlstate.CompanyActorNonce("GET", target, nil), nil)
		response, err := api.ListCompanyAdmissionsWithResponse(t.Context(), team.ID, &authorityv1.ListCompanyAdmissionsParams{XTnlActorToken: token, Cursor: cursor})
		if err != nil || response.JSON200 == nil {
			t.Fatalf("generated admission page client: %+v %v", response, err)
		}
		page := response.JSON200
		if len(page.Requests) > 100 {
			t.Fatal("unbounded admission page")
		}
		for _, row := range page.Requests {
			if row.TeamId != team.ID {
				t.Fatal("admission page crossed teams")
			}
			if len(all) > 0 {
				previous := all[len(all)-1]
				if row.CreatedAt.Before(previous.CreatedAt) || row.CreatedAt.Equal(previous.CreatedAt) && row.RequestId <= previous.RequestId {
					t.Fatal("admission pages overlap or lost bytewise/timestamp ordering")
				}
			}
			all = append(all, row)
		}
		if page.NextCursor == nil {
			break
		}
		if len(page.Requests) == 0 || *page.NextCursor != page.Requests[len(page.Requests)-1].RequestId || cursor != nil && *cursor == *page.NextCursor {
			t.Fatal("admission cursor made no progress")
		}
		// a signed first-page assertion cannot be substituted onto another page.
		f.decode(f.call("GET", path+"?cursor="+*page.NextCursor, companyWebsiteSecret, token, nil), 401, nil)
		cursor = page.NextCursor
	}
	if len(all) != 1002 || all[1001].State != "pending" {
		t.Fatalf("later pending admission undiscoverable: found %d requests", len(all))
	}
	for _, target := range []string{path + "?cursor=caq_0000000000000000000000", path + "?cursor=invalid"} {
		f.decode(f.ownerCall("GET", target, serviceOwnerSub, nil, nil), 400, nil)
	}
}

func TestIntegrationAuthorityProjectManaged(t *testing.T) {
	f, owner, _, team, service := serviceFixture(t)
	if _, err := f.sql.Exec(t.Context(), `INSERT INTO control.local_project_services(team_id,project_key,source_fingerprint,service,worktree_key,private_service_id,created_by_identity_id) VALUES($1,'project',$2,'api','checkout',$3,$4)`, team.ID, strings.Repeat("a", 64), service.ID, owner.Identity.Identity.Id); err != nil {
		t.Fatal(err)
	}
	grants, _, err := f.d.ListPrivateServiceGrants(t.Context(), service.ID, owner.Identity.Identity.Id, "")
	if err != nil || len(grants) != 1 {
		t.Fatal(grants, err)
	}
	if _, err := f.sql.Exec(t.Context(), `UPDATE control.local_project_services SET visitor_grant_id=$1 WHERE private_service_id=$2`, grants[0].ID, service.ID); err != nil {
		t.Fatal(err)
	}
	w := f.serviceCall("DELETE", "/v1/service/private-services/"+service.ID+"/grants/"+grants[0].ID, serviceOwnerSub, nil, nil)
	var problem authorityv1.Problem
	serviceResult(t, w, 409, &problem)
	if string(problem.Code) != "project_managed" || problem.RequestId == "" || problem.Detail != "resource is managed by project configuration; change the declaration and run tnl apply" {
		t.Fatalf("lost project ownership code/action: %+v", problem)
	}
}
