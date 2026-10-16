package controlstate

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testSSHHostKey(t *testing.T, seed byte) string {
	t.Helper()
	value := make([]byte, ed25519.SeedSize)
	value[0] = seed
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(value).Public())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestManagedSSHPublicURLShape(t *testing.T) {
	request := CreatePublicURLRequest{
		TeamID: "team", DomainID: "domain", ActingIdentityID: "identity", IdempotencyKey: "create",
		CanonicalHostname: "ssh.example.test", PublicURLScope: PublicURLScopeShared,
		Purpose: PublicURLPurposeApp, DNSState: PublicURLDNSUnmanaged,
		ServiceProtocol: PublicURLServiceSSH, AccessMode: VisitorAccessRestricted, SSHHostKey: testSSHHostKey(t, 1),
	}
	if _, err := validateCreatePublicURLRequest(request); err != nil {
		t.Fatalf("managed SSH shape rejected: %v", err)
	}
	for name, mutate := range map[string]func(*CreatePublicURLRequest){
		"missing key":       func(r *CreatePublicURLRequest) { r.SSHHostKey = "" },
		"invalid key":       func(r *CreatePublicURLRequest) { r.SSHHostKey = "private key" },
		"anonymous":         func(r *CreatePublicURLRequest) { r.AccessMode = VisitorAccessAnonymous },
		"ephemeral":         func(r *CreatePublicURLRequest) { r.Ephemeral = true },
		"private target":    func(r *CreatePublicURLRequest) { r.Target = "http://127.0.0.1:22" },
		"target tls":        func(r *CreatePublicURLRequest) { r.Target = "https://127.0.0.1:22" },
		"http host key":     func(r *CreatePublicURLRequest) { r.ServiceProtocol = PublicURLServiceHTTP },
		"postgres host key": func(r *CreatePublicURLRequest) { r.ServiceProtocol = PublicURLServicePostgres },
		"mysql host key":    func(r *CreatePublicURLRequest) { r.ServiceProtocol = PublicURLServiceMySQL },
		"redis host key":    func(r *CreatePublicURLRequest) { r.ServiceProtocol = PublicURLServiceRedis },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := request
			mutate(&invalid)
			if _, err := validateCreatePublicURLRequest(invalid); !errors.Is(err, ErrPublicURLInvalid) {
				t.Fatalf("invalid shape error = %v", err)
			}
		})
	}
	request.AccessMode = ""
	if _, err := (*Database)(nil).CreatePublicURL(t.Context(), request, time.Now()); err == nil || errors.Is(err, ErrPublicURLInvalid) {
		t.Fatalf("default restricted SSH should reach database boundary: %v", err)
	}
}

func TestPublicURLCreateTargetShape(t *testing.T) {
	for _, protocol := range []PublicURLServiceProtocol{PublicURLServiceHTTP, PublicURLServicePostgres, PublicURLServiceMySQL, PublicURLServiceRedis, PublicURLServiceSSH} {
		if !protocol.ValidCreateTarget(PublicURLPurposeApp, "", false) {
			t.Errorf("saved %s empty target rejected", protocol)
		}
		if protocol != PublicURLServiceHTTP && protocol.ValidCreateTarget(PublicURLPurposeApp, "http://127.0.0.1:3000", false) {
			t.Errorf("%s private target accepted", protocol)
		}
	}
	if PublicURLServiceHTTP.ValidCreateTarget(PublicURLPurposeApp, "", true) {
		t.Fatal("ephemeral HTTP empty target accepted")
	}
	if !PublicURLServiceHTTP.ValidCreateTarget(PublicURLPurposeApp, "http://127.0.0.1:3000", true) {
		t.Fatal("ephemeral HTTP target rejected")
	}
}
