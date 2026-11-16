package public

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceLargeIPPolicyHTTPCreateConfigureAndProtectedRead(t *testing.T) {
	f, session, _, team, _ := serviceFixture(t)
	ctx := t.Context()
	h, err := NewHandler(Config{}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	client, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(session.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	prefixes := func(secondOctet, count int) []string {
		values := make([]string, count)
		for index := range values {
			values[index] = fmt.Sprintf("198.%d.%d.%d/32", secondOctet, index>>8, index&255)
		}
		slices.Sort(values)
		return values
	}
	// the approved TLS name is separate from the private dial address below.
	const targetHostname = "large-policy-target.example.test"
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Value: bytes.Repeat([]byte{1}, 60<<10)}}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if len(bundle) <= 64<<10 || len(bundle) >= 1<<20 {
		t.Fatal("fixture CA must exceed 64 KiB within the existing 1 MiB bundle bound", len(bundle))
	}
	snapshot, err := targettrust.CapturePEM(targetHostname, bundle)
	if err != nil || snapshot.System || !bytes.Equal(snapshot.PEM, bundle) {
		t.Fatal("large fixture is not canonical CA-only target trust", err)
	}
	trust, err := targettrust.NewDeclaration(targetHostname, snapshot.PEM)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, key string, body any, want int, large bool) ([]byte, http.Header) {
		t.Helper()
		var data []byte
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		if large && len(data) <= 64<<10 {
			t.Fatalf("declaration request has only %d bytes, want >64 KiB", len(data))
		}
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+session.AccessToken)
		r.Header.Set("Content-Type", "application/json")
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err = io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("%s %s: status=%d want=%d error=%v body=%s", method, path, response.StatusCode, want, err, data)
		}
		return data, response.Header
	}
	noPolicyLeak := func(data []byte) {
		t.Helper()
		for _, forbidden := range []string{`"configuration"`, `"access"`, `"ip"`, "private-large-policy.internal", "198.18.", "198.19."} {
			if bytes.Contains(data, []byte(forbidden)) {
				t.Fatalf("service summary exposed private policy data: %s", forbidden)
			}
		}
	}
	// 4096 prefixes were never legal under the existing 256-prefix bound.
	// retain >64 KiB transport with a real CA, not an oversized IP-only policy.
	first := prefixes(18, 256)
	configuration := &controlv1.ProjectServiceConfiguration{Target: "https://private-large-policy.internal:3000",
		TargetTls: &controlv1.ProjectTargetTLS{Hostname: trust.Hostname, CaPem: new(string(trust.CAPEM)), Digest: trust.Digest},
		Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{
			Mode: new(controlv1.VisitorAccessMode("anonymous")), Ip: &first,
		}}}
	data, _ := request(http.MethodPost, "/v1/services", "large-policy", controlv1.CreateServiceRequest{
		TeamId: team.ID, Name: "large-policy", Configuration: configuration,
	}, http.StatusCreated, true)
	noPolicyLeak(data)
	var service controlv1.Service
	if err := json.Unmarshal(data, &service); err != nil || service.Id == "" {
		t.Fatal("large policy create did not return its service", err)
	}
	checkServiceTrust := func() {
		t.Helper()
		if service.TargetTls == nil || service.TargetTls.Hostname != targetHostname || service.TargetTls.System ||
			service.TargetTls.Pem == nil || *service.TargetTls.Pem != string(snapshot.PEM) || service.TargetTls.Digest != snapshot.Digest {
			t.Fatal("service lost the exact approved target CA or snapshot digest")
		}
	}
	checkServiceTrust()
	matchesDeclaration := func(value *controlv1.ProjectServiceConfiguration, want []string) bool {
		return value != nil && value.Target == "private-large-policy.internal:3000" &&
			value.TargetTls != nil && value.TargetTls.Hostname == targetHostname &&
			value.TargetTls.CaPem != nil && *value.TargetTls.CaPem == string(trust.CAPEM) && value.TargetTls.Digest == trust.Digest &&
			value.Http != nil && value.Http.Access != nil && value.Http.Access.Mode != nil && *value.Http.Access.Mode == controlv1.Anonymous &&
			value.Http.Access.Ip != nil && len(*value.Http.Access.Ip) == 256 && slices.Equal(*value.Http.Access.Ip, want)
	}
	checkProtected := func(want []string) string {
		t.Helper()
		data, headers := request(http.MethodGet, "/v1/services/"+service.Id+"/configuration", "", nil, http.StatusOK, false)
		if len(data) <= 64<<10 || headers.Get("Cache-Control") != "no-store" || headers.Get("ETag") == "" {
			t.Fatalf("protected large policy response lost bytes or privacy: size=%d headers=%v", len(data), headers)
		}
		var wire controlv1.ProjectServiceConfiguration
		if err := json.Unmarshal(data, &wire); err != nil || !matchesDeclaration(&wire, want) {
			t.Fatal("protected HTTP read changed the exact target trust or complete policy", err)
		}
		read, digest, err := client.GetServiceConfiguration(ctx, service.Id)
		if err != nil || !matchesDeclaration(read, want) || digest == "" || headers.Get("ETag") != fmt.Sprintf("%q", digest) {
			t.Fatal("bounded management client lost the declaration or exact ETag", err)
		}
		persisted, persistedDigest, err := f.d.GetServiceConfiguration(ctx, service.Id, session.Identity.Identity.Id)
		if err != nil || persisted == nil || persisted.HTTP == nil || persisted.HTTP.Access == nil ||
			persisted.Target != "private-large-policy.internal:3000" || persisted.TargetTLS == nil ||
			persisted.TargetTLS.Hostname != targetHostname || persisted.TargetTLS.CAPEM != string(trust.CAPEM) ||
			persisted.TargetTLS.Digest != trust.Digest || persisted.HTTP.Access.Mode != "anonymous" ||
			len(persisted.HTTP.Access.IP) != 256 || !slices.Equal(persisted.HTTP.Access.IP, want) || persistedDigest != digest {
			t.Fatal("HTTP mutation did not persist the exact CA, policy and declaration digest", err)
		}
		return digest
	}
	digest := checkProtected(first)
	update := func(configuration *controlv1.ProjectServiceConfiguration, digest string) controlv1.UpdateServiceRequest {
		return controlv1.UpdateServiceRequest{
			Protocol: service.Protocol, TargetTls: service.TargetTls, PublisherPool: service.PublisherPool,
			ExpectedTrustRevision: service.TrustRevision, Configuration: configuration, ExpectedConfigurationDigest: &digest,
		}
	}
	for _, count := range []int{257, 4096} {
		tooMany := prefixes(18, count)
		invalid := *configuration
		httpSettings, access := *configuration.Http, *configuration.Http.Access
		access.Ip = &tooMany
		httpSettings.Access, invalid.Http = &access, &httpSettings
		before, err := client.ListServices(ctx, team.ID)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("large-policy-reject-%d", count)
		request(http.MethodPost, "/v1/services", name, controlv1.CreateServiceRequest{
			TeamId: team.ID, Name: name, Configuration: &invalid,
		}, http.StatusBadRequest, false)
		after, err := client.ListServices(ctx, team.ID)
		if err != nil || !reflect.DeepEqual(before, after) || checkProtected(first) != digest {
			t.Fatal("invalid create IP count changed inventory or the saved declaration", count, err)
		}
		request(http.MethodPut, "/v1/services/"+service.Id, "", update(&invalid, digest), http.StatusBadRequest, false)
		after, err = client.ListServices(ctx, team.ID)
		if err != nil || !reflect.DeepEqual(before, after) || checkProtected(first) != digest {
			t.Fatal("invalid update IP count changed inventory or the saved declaration", count, err)
		}
	}
	second := prefixes(19, 256)
	configuration.Http.Access.Ip = &second
	data, _ = request(http.MethodPut, "/v1/services/"+service.Id, "", update(configuration, digest), http.StatusOK, true)
	noPolicyLeak(data)
	originalID, originalRevision := service.Id, service.TrustRevision
	if err := json.Unmarshal(data, &service); err != nil || service.Id != originalID || service.TrustRevision != originalRevision {
		t.Fatal("IP-only update changed service identity or target trust revision", err)
	}
	checkServiceTrust()
	if checkProtected(second) == digest {
		t.Fatal("changed IP policy did not change its declaration digest")
	}
	for _, path := range []string{"/v1/services/" + service.Id, "/v1/services?team_id=" + team.ID} {
		data, _ := request(http.MethodGet, path, "", nil, http.StatusOK, false)
		noPolicyLeak(data)
		if path == "/v1/services?team_id="+team.ID && (bytes.Contains(data, []byte(`"target_tls"`)) || bytes.Contains(data, []byte("BEGIN CERTIFICATE"))) {
			t.Fatal("summary inventory exposed the large target CA")
		}
	}
}
