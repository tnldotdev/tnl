package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestHTTPInstallationKeepsFileTrustAfterOverwriteAndDeletion(t *testing.T) {
	registry, authority, control, selection := backgroundFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const responseBody = "HTTPS through captured file trust"
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("installed HTTP target received plaintext")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Target-SNI", r.TLS.ServerName)
		if _, err := io.WriteString(w, responseBody); err != nil {
			t.Error(err)
		}
	}))
	defer target.Close()
	if len(target.Certificate().DNSNames) == 0 {
		t.Fatal("HTTPS fixture has no explicit target TLS hostname")
	}
	hostname := target.Certificate().DNSNames[0]
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw})
	ca := filepath.Join(t.TempDir(), "target.pem")
	if err := os.WriteFile(ca, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	flags := publishCommand{Target: target.URL, Protocol: "http", TargetTLS: new(true), TargetTLSName: hostname,
		tunnelFlags: tunnelFlags{TargetCAFile: filepath.Base(ca)}, projectRoot: filepath.Dir(ca)}
	flags.ServerURL = control.ControlURL()
	captured, err := captureServiceTargetTrust(ctx, flags, controlv1.ServiceProtocolHTTP, flags.Target)
	if err != nil || captured == nil || captured.System || captured.Hostname != hostname || !bytes.Equal(captured.PEM, certificate) {
		t.Fatal("HTTP target trust was not captured from its actual CA file", err)
	}
	control.service.TargetTls = publisheridentity.ServiceTargetTLS(captured)
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		return backgroundClients(control), authority, nil
	}
	var installedID string
	if err := installBackgroundJob(ctx, registry, flags, selection, backgroundPublishFlags{Install: true, ServiceName: "file-trusted-http"},
		strings.NewReader(""), clients, &installedID); err != nil {
		t.Fatal("install file-trusted HTTPS target", err)
	}
	jobs, err := registry.List(ctx)
	if err != nil || len(jobs) != 1 || jobs[0].ID != installedID || authority.redemptions != 1 {
		t.Fatal("HTTPS installation lost its exact job or redeemed another enrollment", err)
	}
	request := func(config *tls.Config) (*http.Response, error) {
		t.Helper()
		transport := &http.Transport{TLSClientConfig: config}
		defer transport.CloseIdleConnections()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
		if err != nil {
			return nil, err
		}
		return (&http.Client{Transport: transport}).Do(request)
	}
	var verifier *tls.Config
	checkInstalled := func(stage string) {
		t.Helper()
		job, err := registry.ResolveJob(ctx, installedID)
		if err != nil || job.Kind != installedjobs.KindService || job.Protocol != config.ProtocolHTTP ||
			job.Target != target.URL || job.ServiceID != control.service.Id || job.PublisherIdentityID != authority.identity.ClientId ||
			job.Trust == nil || job.Trust.System || job.Trust.Hostname != hostname || job.Trust.Digest != captured.Digest ||
			!bytes.Equal(job.Trust.PEM, certificate) {
			t.Fatal("installed HTTP trust changed after "+stage, err)
		}
		data, err := json.Marshal(job)
		if err != nil || bytes.Contains(data, []byte(ca)) || bytes.Contains(data, []byte(filepath.Base(ca))) || bytes.Contains(data, []byte(`"target_ca_pem"`)) ||
			bytes.Contains(data, []byte(`"target_tls_name"`)) {
			t.Fatal("installed HTTP job retained a mutable trust path or second trust representation", err)
		}
		if err := targetplan.PreflightPrivate(ctx, job.TargetPlan()); err != nil {
			t.Fatal("installed HTTPS preflight reread the source file after "+stage, err)
		}
		verifier, err = job.Trust.Verifier()
		if err != nil || verifier.InsecureSkipVerify || verifier.ServerName != hostname || verifier.RootCAs == nil {
			t.Fatal("installed HTTPS verifier dropped the captured name, roots, or verification", err)
		}
		response, err := request(verifier)
		if err != nil {
			t.Fatal("installed trust could not carry HTTPS after "+stage, err)
		}
		body, readErr := io.ReadAll(response.Body)
		readErr = errors.Join(readErr, response.Body.Close())
		if readErr != nil || response.StatusCode != http.StatusOK || string(body) != responseBody ||
			response.Header.Get("X-Target-SNI") != hostname {
			t.Fatal("installed HTTPS lost its exact bytes or explicit TLS name after "+stage, readErr)
		}
	}
	checkInstalled("installation")
	if err := os.WriteFile(ca, []byte("overwritten CA file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureServiceTargetTrust(ctx, flags, controlv1.ServiceProtocolHTTP, flags.Target); !errors.Is(err, targettrust.ErrInvalidBundle) {
		t.Fatal("overwritten CA file was not actually invalid", err)
	}
	checkInstalled("CA file overwrite")
	if err := os.Remove(ca); err != nil {
		t.Fatal(err)
	}
	if err := registry.Stop(ctx, installedID); err != nil {
		t.Fatal(err)
	}
	if err := registry.Start(ctx, installedID); err != nil {
		t.Fatal(err)
	}
	checkInstalled("CA file deletion and registry restart")

	wrongName := verifier.Clone()
	wrongName.ServerName = "wrong-target.example.invalid"
	if response, err := request(wrongName); err == nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Error("HTTP target accepted an unverified TLS hostname")
	} else {
		var mismatch x509.HostnameError
		if !errors.As(err, &mismatch) {
			t.Error("wrong-name control did not fail hostname verification", err)
		}
	}
	wrongRoots := verifier.Clone()
	wrongRoots.RootCAs = x509.NewCertPool()
	if response, err := request(wrongRoots); err == nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Error("HTTP target accepted an untrusted certificate")
	} else {
		var untrusted x509.UnknownAuthorityError
		if !errors.As(err, &untrusted) {
			t.Error("wrong-root control did not fail certificate verification", err)
		}
	}
	if authority.redemptions != 1 {
		t.Fatal("file mutation or registry restart redeemed another enrollment")
	}
}

func TestInvalidHTTPCAFileFailsBeforeEnrollmentOrStateCreation(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(parent, "invalid-target.pem")
	if err := os.WriteFile(ca, []byte("not a CA certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	var requests, managerCalls atomic.Int32
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		t.Error("invalid HTTP CA file reached control before target trust validation")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := io.WriteString(w, `{"code":"unavailable","status":503}`); err != nil {
			t.Error(err)
		}
	}))
	defer control.Close()
	controlCA := filepath.Join(parent, "control.pem")
	if err := os.WriteFile(controlCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: control.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	clientRoot, installedRoot := filepath.Join(parent, "no-client-state"), filepath.Join(parent, "not-installed")
	flags := publishCommand{Target: target.URL, Protocol: "http", TargetTLS: new(true),
		tunnelFlags: tunnelFlags{TargetCAFile: ca},
		remoteFlags: remoteFlags{ServerURL: control.URL, StateDir: clientRoot}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err = runEnrolledBackgroundPublish(ctx, flags, enrolledPublishSelection{EnrollmentKey: "pen_0123456789abcdefghijkl.enrollment-secret"},
		backgroundPublishFlags{Install: true, SystemStateDir: installedRoot, ServerCAFile: controlCA}, io.Discard, strings.NewReader(""),
		installedjobs.ExecutorFunc(func(context.Context, installedjobs.Command) error {
			managerCalls.Add(1)
			return errors.New("invalid target trust reached the supervisor")
		}))
	if !errors.Is(err, targettrust.ErrInvalidBundle) || requests.Load() != 0 || managerCalls.Load() != 0 {
		t.Error("invalid HTTP CA file did not fail before enrollment and installation", err)
	}
	for _, path := range []string{clientRoot, installedRoot} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Error("invalid HTTP CA file created client or installed state", err)
		}
	}
}
