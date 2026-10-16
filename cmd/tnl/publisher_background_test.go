package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type backgroundAuthority struct {
	identity    authorityv1.PublisherEnrollmentResult
	public      ed25519.PublicKey
	redemptions int
}

func (a *backgroundAuthority) RedeemPublisherEnrollment(_ context.Context, _ string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	a.redemptions++
	a.public = append(ed25519.PublicKey(nil), public...)
	return a.identity, nil
}
func (a *backgroundAuthority) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if client != a.identity.ClientId || grant != a.identity.GrantId || key != a.identity.KeyId || !private.Public().(ed25519.PublicKey).Equal(a.public) {
		return "", nativeauth.ErrScope
	}
	return "access-secret", nil
}

type backgroundControl struct {
	nativeauth.NativeControl
	publicURL controlv1.PublicURL
}

func (c *backgroundControl) PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error) {
	return c.publicURL, nil
}

func backgroundFixture(t *testing.T) (*publisherjob.Registry, *backgroundAuthority, *backgroundControl, enrolledPublishSelection) {
	t.Helper()
	owner := os.Geteuid()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := publisherjob.Open(t.Context(), publisherjob.OpenOptions{Root: filepath.Join(parent, "system"), TestOwnerUID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	id := func(prefix string) string {
		result, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	url := id(opaqueid.PublicURLPrefix)
	a := &backgroundAuthority{identity: authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), TeamId: "team", Kind: "saved_url", PublicUrlId: &url}}
	c := &backgroundControl{publicURL: controlv1.PublicURL{Id: url, TeamId: "team", CanonicalHostname: "db.example", LifecycleState: controlv1.Enabled, Purpose: controlv1.App, ServiceProtocol: "postgres"}}
	return r, a, c, enrolledPublishSelection{EnrollmentKey: id(opaqueid.PublisherEnrollmentPrefix) + ".enrollment-secret"}
}

func TestBackgroundInstallsEnrolledTCPJobWithLocalTarget(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	flags := publishCommand{Target: "127.0.0.1:5432", TargetTLS: true, TargetTLSName: "db.internal"}
	flags.ServerURL = "https://control.example"
	bg := backgroundPublishFlags{BG: true, Job: "database"}
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		return c, a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, bg, strings.NewReader(""), clients); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 {
		t.Fatalf("installed jobs: %+v, %v", jobs, err)
	}
	job := jobs[0]
	if job.Protocol != "postgres" || job.Target != flags.Target || !job.TargetTLS || job.TargetTLSName != "db.internal" || job.PublisherID != a.identity.ClientId {
		t.Fatalf("private target settings: %+v", job)
	}
	if c.publicURL.Target != "" {
		t.Fatal("private database target was sent to control")
	}
	if a.redemptions != 1 {
		t.Fatal("enrollment was not redeemed once")
	}
	if err := r.Stop(t.Context(), bg.Job); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(t.Context(), bg.Job); err != nil {
		t.Fatal(err)
	}
	profile, err := r.Profile(t.Context(), flags.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := profile.PublisherSigningIdentity(t.Context(), "publisher:"+a.identity.ClientId); err != nil || !found {
		t.Fatalf("stop revoked/removed identity: %v", err)
	}
}

func TestBackgroundImportsPortableFileWithoutRedeemingEnrollment(t *testing.T) {
	r, a, c, _ := backgroundFixture(t)
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a.public = private.Public().(ed25519.PublicKey)
	f, err := credentialfile.New("https://control.example", a.identity, private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := credentialfile.Write(path, f); err != nil {
		t.Fatal(err)
	}
	flags := publishCommand{Target: "127.0.0.1:5432"}
	flags.ServerURL = f.ControlURL
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		return c, a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, enrolledPublishSelection{PublisherFile: path}, backgroundPublishFlags{BG: true, Job: "database"}, strings.NewReader(""), clients); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].PublisherID != a.identity.ClientId || a.redemptions != 0 {
		t.Fatalf("import did not reuse the saved identity: jobs=%v, redemptions=%d, err=%v", jobs, a.redemptions, err)
	}
}

func TestBackgroundRejectsNamespaceEphemeralAndImplicitServer(t *testing.T) {
	for _, kind := range []string{"namespace", "ephemeral", "implicit server", "policy", "open"} {
		t.Run(kind, func(t *testing.T) {
			r, a, c, selection := backgroundFixture(t)
			flags := publishCommand{Target: "3000"}
			flags.ServerURL = "https://control.example"
			switch kind {
			case "namespace":
				a.identity.Kind, a.identity.PublicUrlId = "namespace", nil
				namespace, domain := "member.example", func() string { v, _ := opaqueid.New(opaqueid.DomainPrefix); return v }()
				a.identity.Namespace, a.identity.DomainId = &namespace, &domain
			case "ephemeral":
				c.publicURL.Ephemeral = true
			case "implicit server":
				flags.ServerURL = ""
			case "policy":
				flags.Anonymous = true
			case "open":
				flags.Open = true
			}
			clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
				return c, a, nil
			}
			err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{BG: true, Job: "one"}, strings.NewReader(""), clients)
			if err == nil {
				t.Fatal("invalid background scope installed")
			}
			jobs, err := r.List(t.Context())
			if err != nil || len(jobs) != 0 {
				t.Fatalf("partial job installed: %+v, %v", jobs, err)
			}
		})
	}
}
