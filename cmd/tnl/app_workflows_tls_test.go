package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisheridentity/native/publishingtest"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func appWorkflowTLSTarget(t *testing.T) (string, string, <-chan struct{}) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"target.internal"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "mounted target") }))
	verified := make(chan struct{}, 8)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, VerifyConnection: func(cs tls.ConnectionState) error {
		if cs.ServerName == "target.internal" {
			verified <- struct{}{}
		}
		return nil
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return server.URL, ca, verified
}

func TestAppWorkflowStaticMountPreservesTargetAndTLSName(t *testing.T) {
	a, _ := testAppRuntime(t)
	target, ca, _ := appWorkflowTLSTarget(t)
	a.project.Root = filepath.Dir(ca)
	ca = filepath.Base(ca)
	a.project.Config.Services = config.Services{
		"web": {HTTP: &config.HTTPService{Paths: map[string]config.PathMount{"/api": {Service: "api", StripPrefix: true}}}},
		"api": {Target: &config.ServiceTarget{Type: "address", Address: new(config.Target(target)), TLS: &config.TargetTLS{ServerName: new("target.internal"), CAFile: &ca}}},
	}
	mounts, err := a.resolveRuntimeMounts(a.project, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 {
		t.Fatalf("mounts=%+v", mounts)
	}
	mount := mounts[0]
	resolved := mount.Target
	if mount.ResolveTarget != nil {
		resolved = mount.ResolveTarget()
	}
	if resolved != target {
		t.Fatalf("static target was replaced by app registration lookup: %q", resolved)
	}
	if mount.Options.ServerName != "target.internal" {
		t.Fatalf("mounted TLS name lost: %+v", mount.Options)
	}
	if err := localproxy.PreflightWithOptions(t.Context(), resolved, mount.Options); err != nil {
		t.Fatal(err)
	}
	proxy, err := localproxy.NewWithMountsHooksOptions(target, "public.example", 2, mounts, localproxy.ResponseHooks{}, mount.Options)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "https://public.example/api/health", nil)
	request.RequestURI = request.URL.RequestURI()
	request.URL.Scheme, request.URL.Host = "", ""
	request.TLS = &tls.ConnectionState{ServerName: "public.example"}
	proxy.ServeHTTP(response, request)
	if response.Code != 200 || response.Body.String() != "mounted target" {
		t.Fatalf("mounted TLS request: %d %s", response.Code, response.Body)
	}
}

func TestAppWorkflowEnrolledPreflightPreservesTLSName(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	target, ca, verified := appWorkflowTLSTarget(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	f := publishingtest.New(t, testutil.PublishingHooks{})
	route, err := f.SavedURL(ctx, controlv1.App, target)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := f.Owner()
	enrollment, err := owner.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: route.TeamId, PublicUrlId: &route.Id, Name: "tls", Kind: "installed"})
	if err != nil {
		t.Fatal(err)
	}
	state, err := clientstate.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := state.Server(ctx, f.URL)
	authority, _ := authorityclient.New(f.URL, f.HTTP, "")
	_, identity, err := nativeauth.EnrollNative(ctx, profile, owner, authority, enrollment.EnrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	root := state.Root()
	_ = state.Close()
	original := http.DefaultTransport
	http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == f.URL {
			return f.HTTP.Transport.RoundTrip(r)
		}
		return original.RoundTrip(r)
	})
	defer func() { http.DefaultTransport = original }()
	flags := publishCommand{Target: target, TargetTLSName: "target.internal", remoteFlags: remoteFlags{ServerURL: f.URL, StateDir: root}, tunnelFlags: tunnelFlags{TargetCAFile: ca, InspectionMode: "none"}}
	output, _ := newPublishOutput(publishOutputNDJSON, "tnl publish", io.Discard, io.Discard, nil)
	err = runEnrolledPublish(ctx, flags, enrolledPublishSelection{PublisherID: identity.ClientId}, output, nil, nil)
	select {
	case <-verified:
	default:
		t.Fatalf("enrolled publisher never passed target TLS preflight: %v", err)
	}
}
