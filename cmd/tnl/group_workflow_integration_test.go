package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/connector"

	"github.com/jackc/pgx/v5"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlrelay "github.com/tnldotdev/tnl/internal/control/api/private/relay"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/development/oidc"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/local"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var cliWorkflowChild = flag.Bool("tnl-cli-workflow-child", false, "isolate the CLI workflow's local infrastructure trust")

// this uses the real CLI dispatcher, protected task keys, PostgreSQL authority,
// relay claims and ingress forwarding. only the infrastructure CA is local.
func TestIntegrationCLIApplyGroupServeConnect(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/cli/workflow.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture Git setup: %v %s", err, output)
		}
	}
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "CLI workflow", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity().PersonalTeamId
	control := session.Authenticated().Control
	t.Cleanup(func() { _ = session.Close() })
	var operations atomic.Int64
	var webhookBody atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			operations.Add(1)
			body, _ := io.ReadAll(r.Body)
			if r.URL.Path == "/hooks/review" {
				webhookBody.Store(string(body))
			}
			_, _ = w.Write(body)
			return
		}
		_, _ = io.WriteString(w, "local application")
	}))
	t.Cleanup(target.Close)
	configuration := filepath.Join(root, "tnl.json")
	data, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{"server": f.url, "team": team, "oauth": true, "webhooks": map[string]any{"review": map[string]any{"service": "web", "path": "/hooks/review", "provider": "custom", "source_ips": []string{"127.0.0.1"}}}, "publisher_groups": map[string]any{"cluster": map[string]any{"description": "CLI workflow"}, "external": map[string]any{"public": true}}, "services": map[string]any{
		"api":       map[string]any{"publisher_group": "cluster", "target": map[string]any{"type": "address", "address": target.URL}, "access": map[string]any{"team": true}},
		"publicapi": map[string]any{"publisher_group": "external", "target": map[string]any{"type": "address", "address": target.URL}, "http": map[string]any{}, "access": map[string]any{"team": true}},
		"internal":  map[string]any{"name": "local-internal", "target": map[string]any{"type": "app"}, "access": map[string]any{"team": true}},
		"web":       map[string]any{"target": map[string]any{"type": "app"}, "public_url": map[string]any{"access": "anonymous"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	result := cliCall(t, t.Context(), []string{"--config", configuration, "apply", "--state-dir", person, "--output", "json"})
	var applied controlv1.AppliedProjectConfiguration
	if err := json.Unmarshal(result, &applied); err != nil || applied.Revision != 1 {
		t.Fatalf("applied configuration: %v", err)
	}
	if !applied.Configuration.Oauth || len(applied.Configuration.Webhooks) != 1 || applied.Configuration.Webhooks["review"].Path != "/hooks/review" {
		t.Fatal("root OAuth/webhook declarations did not reach real control")
	}
	var serviceID string
	for _, s := range applied.Services {
		if s.Service == "api" && s.ServiceKind == "service" && s.ServiceId != nil {
			serviceID = *s.ServiceId
		}
	}
	if serviceID == "" {
		t.Fatal("apply did not create the private HTTP service")
	}
	cliCall(t, t.Context(), []string{"--config", configuration, "generate"})
	runtimeCtx, stopRuntime := context.WithCancel(t.Context())
	runtimeDone := make(chan error, 1)
	go func() { runtimeDone <- runRuntimeServe(runtimeCtx, runtimeOptions{Directory: root, StateDir: person}) }()
	t.Cleanup(func() {
		stopRuntime()
		select {
		case err := <-runtimeDone:
			if err != nil {
				t.Errorf("local app owner shutdown: %v", err)
			}
		case <-time.After(12 * time.Second):
			t.Error("local app owner did not join")
		}
	})
	var endpoint publisherprotocol.Endpoint
	workflowWait(t, 5*time.Second, func() bool {
		descriptor, err := publisherprotocol.DescriptorPath(person, root)
		if err != nil {
			return false
		}
		endpoint, err = publisherprotocol.ReadEndpoint(descriptor)
		return err == nil && local.Available(t.Context(), endpoint)
	})
	web := "web"
	var appEndpoint publisherprotocol.Endpoint
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/capabilities", publisherprotocol.CapabilityRequest{Scope: "app", Service: &web}, &appEndpoint); err != nil {
		t.Fatal(err)
	}
	owner := strings.Repeat("a", 32)
	var assignment publisherprotocol.Assignment
	if err := publisherprotocol.Call(t.Context(), appEndpoint, "POST", "/v1/prepare", publisherprotocol.Prepare{Version: 1, Service: web, Directory: root, Framework: "node", Owner: owner, PID: os.Getpid()}, &assignment); err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile(filepath.Join(root, ".tnl", "local", "project.json"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := meta.Parse(metadata)
	if err != nil || len(public.Services) != 3 || public.Services["web"].URL == "" || public.Services["publicapi"].URL == "" || public.Services["api"].URL == "" || public.Services["api"].Public || bytes.Contains(metadata, []byte(target.URL)) {
		t.Fatalf("browser metadata lost endpoint scope or leaked a target: %v", err)
	}
	if _, found := public.Services["internal"]; found {
		t.Fatal("private app listener received browser metadata")
	}
	if err := publisherprotocol.Call(t.Context(), appEndpoint, "POST", "/v1/register", publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: owner, Target: target.URL}, nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = publisherprotocol.Call(context.Background(), appEndpoint, "POST", "/v1/unregister", publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: owner, Target: target.URL}, nil)
	}()
	registrationCtx, stopRegistration := context.WithCancel(t.Context())
	registrationDone := make(chan struct{})
	go func() {
		defer close(registrationDone)
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-registrationCtx.Done():
				return
			case <-ticker.C:
				_ = publisherprotocol.Call(registrationCtx, appEndpoint, "POST", "/v1/renew", publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: owner, Target: target.URL}, nil)
			}
		}
	}()
	defer func() { stopRegistration(); <-registrationDone }()
	visitor := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
	lastPublicState := ""
	workflowWait(t, 25*time.Second, func() bool {
		response, err := visitor.Get(assignment.PublicURL)
		if err != nil {
			state := "transport: " + err.Error()
			if state != lastPublicState {
				t.Log(state)
				lastPublicState = state
			}
			return false
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		state := fmt.Sprintf("HTTP %d, diagnostic %s", response.StatusCode, response.Header.Get("Tnl-Error-Code"))
		if state != lastPublicState {
			t.Log(state)
			lastPublicState = state
		}
		return response.StatusCode == 200 && string(body) == "local application"
	})
	workflowWait(t, 5*time.Second, func() bool {
		var snapshot publisherapp.Snapshot
		services := []string{"web"}
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/check", publisherprotocol.Check{Services: &services}, &snapshot); err != nil {
			return false
		}
		for _, s := range snapshot.Services {
			if s.Name == "web" {
				return s.Ready
			}
		}
		return false
	})
	if len(assignment.Project.Webhooks) != 1 {
		t.Fatal("local webhook metadata was not generated")
	}
	webhookURL := assignment.Project.Webhooks["review"].URL
	lastWebhookState := ""
	workflowWait(t, 25*time.Second, func() bool {
		response, err := visitor.Post(webhookURL, "application/octet-stream", strings.NewReader("public webhook delivery"))
		if err != nil {
			state := "transport: " + err.Error()
			if state != lastWebhookState {
				t.Log(state)
				lastWebhookState = state
			}
			return false
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		state := fmt.Sprintf("HTTP %d, diagnostic %s", response.StatusCode, response.Header.Get("Tnl-Error-Code"))
		if state != lastWebhookState {
			t.Log(state)
			lastWebhookState = state
			if snapshot, err := session.Database().SnapshotProject(t.Context(), root); err == nil {
				for _, integration := range snapshot.IntegrationURLs {
					t.Logf("integration %s: %s %s", integration.Kind, integration.State, integration.Reason)
					for _, endpoint := range integration.Endpoints {
						t.Logf("endpoint %s: %s %s, receivers=%d", endpoint.Name, endpoint.State, endpoint.Reason, len(endpoint.ReadyReceivers))
					}
				}
			}
		}
		return response.StatusCode == 200 && len(body) == 0 && webhookBody.Load() == "public webhook delivery"
	})
	operations.Store(0)
	var localSnapshot publisherapp.Snapshot
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &localSnapshot); err != nil || len(localSnapshot.Services) != 2 {
		t.Fatal("remote group services were registered with the local app owner")
	}
	var privateAppEndpoint publisherprotocol.Endpoint
	internal := "internal"
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/capabilities", publisherprotocol.CapabilityRequest{Scope: "app", Service: &internal}, &privateAppEndpoint); err != nil {
		t.Fatal(err)
	}
	privateOwner := strings.Repeat("b", 32)
	var privateAssignment publisherprotocol.Assignment
	if err := publisherprotocol.Call(t.Context(), privateAppEndpoint, "POST", "/v1/prepare", publisherprotocol.Prepare{Version: 1, Service: internal, Directory: root, Framework: "node", Owner: privateOwner, PID: os.Getpid()}, &privateAssignment); err != nil {
		t.Fatal(err)
	}
	if privateAssignment.PublicURL != "" || privateAssignment.Hostname != "" {
		t.Fatal("private app was assigned a public hostname")
	}
	privateRegistration := publisherprotocol.Registration{Version: 1, RegistrationID: privateAssignment.RegistrationID, Owner: privateOwner, Target: target.URL}
	if err := publisherprotocol.Call(t.Context(), privateAppEndpoint, "POST", "/v1/register", privateRegistration, nil); err != nil {
		t.Fatal(err)
	}
	privateCtx, stopPrivateApp := context.WithCancel(t.Context())
	privateDone := make(chan struct{})
	go func() {
		defer close(privateDone)
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-privateCtx.Done():
				return
			case <-ticker.C:
				_ = publisherprotocol.Call(privateCtx, privateAppEndpoint, "POST", "/v1/renew", privateRegistration, nil)
			}
		}
	}()
	defer func() {
		stopPrivateApp()
		<-privateDone
		_ = publisherprotocol.Call(context.Background(), privateAppEndpoint, "POST", "/v1/unregister", privateRegistration, nil)
	}()
	workflowWait(t, 20*time.Second, func() bool {
		services := []string{internal}
		var snapshot publisherapp.Snapshot
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/check", publisherprotocol.Check{Services: &services}, &snapshot); err != nil {
			return false
		}
		for _, s := range snapshot.Services {
			if s.Name == internal {
				return s.Registered && s.Routable && s.Ready && s.RunNumber > 0 && s.PublicURL == ""
			}
		}
		return false
	})
	localListener := workflowListen(t)
	localAddress := localListener.Addr().String()
	_ = localListener.Close()
	localConnectCtx, stopLocalConnect := context.WithCancel(t.Context())
	f.command(t, localConnectCtx, stopLocalConnect, []string{"--config", configuration, "connect", internal, "--listen", localAddress, "--state-dir", person})
	project, err := loadProjectConfiguration(t.Context(), cli{ConfigPath: configuration}, person)
	if err != nil {
		t.Fatal(err)
	}
	localService, err := connector.Select(t.Context(), control, project.Project, internal, team)
	if err != nil {
		t.Fatal(err)
	}
	localClient := workflowNativeHTTPClient(t, f, localService.Endpoint.Hostname)
	workflowWait(t, 10*time.Second, func() bool {
		response, err := localClient.Get("https://" + localAddress + "/private-app")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode == 200 && string(body) == "local application"
	})
	localResponse, err := localClient.Post("https://"+localAddress+"/private-app", "application/octet-stream", strings.NewReader("configured local key request body"))
	if err != nil {
		t.Fatal(err)
	}
	localBody, err := io.ReadAll(localResponse.Body)
	_ = localResponse.Body.Close()
	if err != nil || localResponse.StatusCode != 200 || string(localBody) != "configured local key request body" || operations.Load() != 1 {
		t.Fatalf("configured local connect changed request bytes: %q, count=%d, err=%v", localBody, operations.Load(), err)
	}
	operations.Store(0)
	aliasListener := workflowListen(t)
	aliasAddress := aliasListener.Addr().String()
	_ = aliasListener.Close()
	aliasCtx, stopAliasConnect := context.WithCancel(t.Context())
	f.command(t, aliasCtx, stopAliasConnect, []string{"--config", configuration, "connect", "local-internal", "--listen", aliasAddress, "--state-dir", person})
	workflowWait(t, 10*time.Second, func() bool {
		response, err := localClient.Get("https://" + aliasAddress + "/private-app-override")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode == 200 && string(body) == "local application"
	})
	bootstrap := strings.TrimSpace(string(cliCall(t, t.Context(), []string{"--config", configuration, "publisher", "enroll", "--group", "cluster", "--members", "2", "--expires-in", "1h", "--state-dir", person})))
	externalKey := strings.TrimSpace(string(cliCall(t, t.Context(), []string{"--config", configuration, "publisher", "enroll", "--group", "external", "--members", "1", "--expires-in", "1h", "--state-dir", person})))
	externalCtx, stopExternal := context.WithCancel(t.Context())
	f.command(t, externalCtx, stopExternal, []string{"--no-config", "publisher", "serve", "--group", "external", "--project-key", applied.ProjectKey, "--instance", "public", "--enroll-key", externalKey, "--server", f.url, "--state-dir", f.state(t, "external")})
	if bootstrap == "" || strings.ContainsAny(bootstrap, "\r\n ") || strings.Contains(bootstrap, "+--") {
		t.Fatal("group bootstrap was not one exact raw secret")
	}
	var members []string
	var taskCancels []context.CancelFunc
	var taskStates []string
	var taskJoins []<-chan struct{}
	for _, instance := range []string{"one", "two"} {
		state := f.state(t, "task-"+instance)
		taskStates = append(taskStates, state)
		ctx, cancel := context.WithCancel(t.Context())
		taskCancels = append(taskCancels, cancel)
		_, joined := f.command(t, ctx, cancel, []string{"--no-config", "publisher", "serve", "--group", "cluster", "--project-key", applied.ProjectKey, "--instance", instance, "--enroll-key", bootstrap, "--server", f.url, "--state-dir", state})
		taskJoins = append(taskJoins, joined)
	}
	groupWaitStarted := time.Now()
	loggedRuns := false
	workflowWait(t, 35*time.Second, func() bool {
		if time.Since(groupWaitStarted) > 20*time.Second && !loggedRuns {
			f.logRuns(t)
			loggedRuns = true
		}
		status, err := control.GetProjectConfiguration(t.Context(), team, applied.ProjectKey)
		if err != nil || len(status.Members) != 3 {
			return false
		}
		members = nil
		for _, m := range status.Members {
			if !m.Healthy || m.ObservedRevision != applied.Revision {
				return false
			}
			if m.GroupName == "cluster" {
				members = append(members, m.PublisherIdentityId)
			}
		}
		return true
	})
	if members[0] == members[1] {
		t.Fatal("replicas shared a publisher identity")
	}
	var directService controlv1.Service
	for _, service := range applied.Services {
		if service.Service == "publicapi" && service.ServiceId != nil {
			directService, err = control.GetService(t.Context(), *service.ServiceId)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if directService.Endpoint == nil || !directService.Endpoint.Public {
		t.Fatal("public group lost service HTTP endpoint")
	}
	f.connectDirectListener(t, directService.Endpoint)
	grant, err := control.CreateServiceHTTPGrant(t.Context(), directService.Id, controlv1.CreateServiceHTTPGrantRequest{Kind: "token", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	workflowWait(t, 10*time.Second, func() bool {
		request, err := http.NewRequestWithContext(t.Context(), "GET", public.Services["publicapi"].URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Tnl-Access-Token", grant.Secret)
		response, err := visitor.Do(request)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode == 200 && string(body) == "local application"
	})
	listen := workflowListen(t)
	address := listen.Addr().String()
	_ = listen.Close()
	connectCtx, stopConnect := context.WithCancel(t.Context())
	f.command(t, connectCtx, stopConnect, []string{"--config", configuration, "connect", "api", "--listen", address, "--state-dir", person})
	savedService, err := control.GetService(t.Context(), serviceID)
	if err != nil {
		t.Fatal(err)
	}
	client := workflowNativeHTTPClient(t, f, savedService.Endpoint.Hostname)
	workflowWait(t, 15*time.Second, func() bool {
		response, err := client.Get("https://" + address + "/ready")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == 200
	})
	response, err := client.Post("https://"+address+"/once", "application/octet-stream", strings.NewReader("through the real private publisher"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "through the real private publisher" || operations.Load() != 1 {
		t.Fatalf("private HTTP bytes or operation count changed: count=%d err=%v", operations.Load(), err)
	}
	taskCancels[0]()
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	workflowWait(t, 15*time.Second, func() bool {
		response, err := client.Get("https://" + address + "/surviving-replica")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == 200
	})
	audit := cliCall(t, t.Context(), []string{"--no-config", "audit", "list", "--team", team, "--service", serviceID, "--since", "1h", "--output", "json", "--server", f.url, "--state-dir", person})
	select {
	case <-taskJoins[0]:
	case <-time.After(35 * time.Second):
		t.Fatal("stopped group task did not join")
	}
	restartCtx, stopRestart := context.WithCancel(t.Context())
	restarted, _ := f.command(t, restartCtx, stopRestart, []string{"--no-config", "publisher", "serve", "--group", "cluster", "--project-key", applied.ProjectKey, "--instance", "one", "--enroll-key", bootstrap, "--server", f.url, "--state-dir", taskStates[0]})
	select {
	case <-restarted:
	case <-time.After(25 * time.Second):
		t.Fatal("persisted task did not restart with its own key")
	}
	workflowWait(t, 20*time.Second, func() bool {
		status, err := control.GetProjectConfiguration(t.Context(), team, applied.ProjectKey)
		if err != nil || len(status.Members) != 3 {
			return false
		}
		for _, member := range status.Members {
			if !member.Healthy || member.ObservedRevision != applied.Revision {
				return false
			}
			if member.GroupName == "cluster" && member.PublisherIdentityId != members[0] && member.PublisherIdentityId != members[1] {
				t.Fatal("restarted task consumed another enrollment member")
			}
		}
		return true
	})
	var page controlv1.ServiceAuditPage
	if err := json.Unmarshal(audit, &page); err != nil || len(page.Events) == 0 {
		t.Fatalf("real control audit was not readable: %v", err)
	}
	t.Log("CLI apply -> real local public app/webhook and private app readiness/traffic -> two signed group tasks running public.Run and privatepublisher.Publish -> authenticated connect -> private HTTP bytes; portable generation, runtime endpoint metadata, and audit read passed")
}

type cliWorkflow struct {
	directConnector         *ingress.Connector
	url                     string
	publicAddress           string
	databaseURL             string
	issuer                  *x509.Certificate
	issuerKey               ed25519.PrivateKey
	tls                     *tls.Config
	ctx                     context.Context
	cancel                  context.CancelFunc
	workers                 sync.WaitGroup
	groupEnrollmentRequests atomic.Int64
	beforeVisitorInventory  atomic.Pointer[func()]
	certificateWorkPaused   atomic.Bool
}

func newCLIWorkflow(t *testing.T) *cliWorkflow {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CLI workflow infrastructure"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(certificate)
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	x509.SetFallbackRoots(roots)
	ctx, cancel := context.WithCancel(context.Background())
	f := &cliWorkflow{ctx: ctx, cancel: cancel, issuer: certificate, issuerKey: key, tls: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: certificate}}}}
	t.Cleanup(cancel)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "cli-group-workflow")
	f.databaseURL = databaseURL
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	server.TLS = f.tls.Clone()
	server.StartTLS()
	t.Cleanup(server.Close)
	f.url = server.URL
	providerMux := http.NewServeMux()
	provider := httptest.NewUnstartedServer(providerMux)
	provider.TLS = f.tls.Clone()
	provider.StartTLS()
	t.Cleanup(provider.Close)
	identityProvider, err := oidc.New(oidc.Config{Issuer: provider.URL, ClientID: "server", ClientSecret: "fixture-secret", Subject: "developer", RedirectURLs: []string{f.url + "/v1/auth/device/callback", f.url + "/v1/browser/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	providerMux.Handle("/", identityProvider)
	if err := database.SeedHumanAuthentication(t.Context(), "apps.integration.test", controlstate.HumanAuthenticationSeeds{Issuer: provider.URL, Administrators: []string{"developer"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := database.PrepareVisitorSigningKeys(t.Context(), f.url, time.Now()); err != nil {
		t.Fatal(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(address)
		if strings.HasSuffix(host, ".apps.integration.test") && f.publicAddress != "" {
			if port == "443" {
				address = f.publicAddress
			} else {
				address = net.JoinHostPort("127.0.0.1", port)
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	const directory = "https://ca.integration.test/directory"
	account, err := database.EnsureACMEAccount(t.Context(), directory, "cli@example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpdateACMEAccountRegistration(t.Context(), account.ID, account.ContactEmail, "https://ca.integration.test/account", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	handler, err := controlpublic.NewHandler(controlpublic.Config{Role: daemonconfig.RoleControl, ControlURL: f.url, ManagedDomain: "apps.integration.test", ManagedURLMode: naming.ManagedURLModeSimple, OIDCIssuer: provider.URL, OIDCClientID: "server", OIDCClientSecret: "fixture-secret", OIDCScopes: []string{"openid"}, AccessTokenLifetime: time.Hour, RefreshTokenLifetime: 24 * time.Hour, CertificateIssuance: true, DNSAutomation: true, ACMEDirectoryURL: directory}, database, database, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := controlauthority.NewHandler(controlauthority.Config{ControlURL: f.url, ManagedDomain: "apps.integration.test", OIDCIssuer: provider.URL, OIDCClientID: "server", OIDCClientSecret: "fixture-secret", OIDCScopes: []string{"openid"}, AccessTokenLifetime: time.Hour, RefreshTokenLifetime: 24 * time.Hour}, database)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/visitor/services" {
			if hook := f.beforeVisitorInventory.Load(); hook != nil {
				(*hook)()
			}
		}
		if r.Method == http.MethodPost && (r.URL.Path == "/v1/publisher-groups/enroll" || strings.Contains(r.URL.Path, "/enrollments")) {
			f.groupEnrollmentRequests.Add(1)
		}
		capture := &workflowProblemWriter{ResponseWriter: w}
		_, pattern := authority.Handler(r)
		if pattern != "/" {
			authority.ServeHTTP(capture, r)
		} else {
			handler.ServeHTTP(capture, r)
		}
		if capture.status >= 400 && capture.status != 404 {
			var problem controlv1.Problem
			if json.Unmarshal(capture.body.Bytes(), &problem) == nil {
				t.Logf("control %s %s: %d %s: %s", r.Method, r.URL.Path, capture.status, problem.Code, problem.Detail)
			}
		}
	}))
	for _, id := range []string{"cli-relay-a", "cli-relay-b"} {
		f.relay(t, database, id)
	}
	for _, id := range []string{"cli-ingress-a", "cli-ingress-b"} {
		f.ingress(t, database, id)
	}
	f.workers.Go(func() { f.certificateWork(t, database) })
	f.workers.Go(func() { f.dnsWork(t, database) })
	t.Cleanup(func() { cancel(); f.workers.Wait() })
	return f
}

func (f *cliWorkflow) dnsWork(t *testing.T, database *controlstate.Database) {
	for f.ctx.Err() == nil {
		now := time.Now()
		public, found, err := database.ClaimDNSPublicURLWork(f.ctx, "cli-dns", now, time.Minute)
		if err == nil && found {
			if public.State == controlstate.PublicURLDNSRemoving {
				public.State = controlstate.PublicURLDNSRemoved
			} else {
				public.State = controlstate.PublicURLDNSPublished
			}
			public.AvailableAt = time.Time{}
			_, err = database.SaveDNSPublicURLWork(f.ctx, public, time.Now())
		}
		if err != nil && !errors.Is(err, controlstate.ErrDNSPublicURLWorkStale) && f.ctx.Err() == nil {
			t.Error("local DNS public URL exchange", err)
			return
		}
		managed, found, err := database.ClaimServiceEndpointDNSWork(f.ctx, "cli-dns", now, time.Minute)
		if err == nil && found {
			if managed.State == controlstate.PublicURLDNSRemoving {
				managed.State = controlstate.PublicURLDNSRemoved
			} else {
				managed.State = controlstate.PublicURLDNSPublished
			}
			managed.AvailableAt = time.Time{}
			_, err = database.SaveServiceEndpointDNSWork(f.ctx, managed, time.Now())
		}
		if err != nil && !errors.Is(err, controlstate.ErrDNSPublicURLWorkStale) && f.ctx.Err() == nil {
			t.Error("local DNS service exchange", err)
			return
		}
		select {
		case <-f.ctx.Done():
			return
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (f *cliWorkflow) logRuns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, f.databaseURL)
	if err != nil {
		t.Logf("inspect workflow state: %v", err)
		return
	}
	defer connection.Close(ctx)
	rows, err := connection.Query(ctx, `SELECT u.canonical_hostname,coalesce(r.publisher_identity_id,''),r.state,r.certificate_installed_at IS NOT NULL FROM control.publish_runs r JOIN control.public_urls u ON u.id=r.public_url_id WHERE r.closed_at IS NULL ORDER BY u.canonical_hostname,r.publish_run_number`)
	if err != nil {
		t.Logf("inspect active runs: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var host, id, state string
		var certificate bool
		if err := rows.Scan(&host, &id, &state, &certificate); err == nil {
			t.Logf("active public run %s publisher=%s state=%s certificate=%t", host, id, state, certificate)
		}
	}
}

type workflowProblemWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *workflowProblemWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *workflowProblemWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if w.status >= 400 && w.body.Len()+len(data) <= 16384 {
		_, _ = w.body.Write(data)
	}
	return w.ResponseWriter.Write(data)
}

func (f *cliWorkflow) state(t *testing.T, name string) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "tnl-cli-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	root := filepath.Join(directory, name)
	database, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	return root
}

func (f *cliWorkflow) loginPerson(t *testing.T, person string) {
	t.Helper()
	var op clientstate.AuthOperation
	payload := cliCall(t, t.Context(), []string{"--no-config", "auth", "login", "start", "--output=json", "--server", f.url, "--state-dir", person})
	if err := json.Unmarshal(payload, &op); err != nil {
		t.Fatal(err)
	}
	if err := oidctest.Approve(t.Context(), http.DefaultClient, op.ApprovalURL); err != nil {
		t.Fatal(err)
	}
	cliCall(t, t.Context(), []string{"--no-config", "auth", "login", "wait", op.ID, "--output=json", "--server", f.url, "--state-dir", person})
}

func cliCall(t *testing.T, ctx context.Context, args []string) []byte {
	t.Helper()
	var output, diagnostics bytes.Buffer
	if err := run(ctx, append([]string{"--no-telemetry"}, args...), &output, &diagnostics); err != nil {
		t.Fatalf("CLI %s: %v\n%s", args[0], err, diagnostics.String())
	}
	return output.Bytes()
}

func (f *cliWorkflow) command(t *testing.T, ctx context.Context, cancel context.CancelFunc, args []string) (<-chan struct{}, <-chan struct{}) {
	t.Helper()
	done := make(chan error, 1)
	joined := make(chan struct{})
	ready := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(joined)
		done <- run(ctx, append([]string{"--no-telemetry"}, args...), io.Discard, workflowLifecycleLog{t: t, ready: func() { once.Do(func() { close(ready) }) }})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("joined CLI lifecycle: %v", err)
			}
		case <-time.After(40 * time.Second):
			t.Error("CLI lifecycle did not join")
		}
	})
	return ready, joined
}

type workflowLifecycleLog struct {
	t     *testing.T
	ready func()
}

func (w workflowLifecycleLog) Write(value []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(value)))
	if w.ready != nil && bytes.Contains(value, []byte("]-- ready ")) {
		w.ready()
	}
	return len(value), nil
}

func workflowListen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}
func workflowWait(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("CLI workflow condition did not become ready")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (f *cliWorkflow) serve(t *testing.T, listener net.Listener, accept func(net.Conn) error) {
	t.Helper()
	t.Cleanup(func() { _ = listener.Close() })
	context.AfterFunc(f.ctx, func() { _ = listener.Close() })
	f.workers.Go(func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			f.workers.Go(func() { defer connection.Close(); _ = accept(connection) })
		}
	})
}

const cliWorkflowClusterSecret = "0123456789abcdef0123456789abcdef"

func (f *cliWorkflow) relay(t *testing.T, database *controlstate.Database, id string) {
	t.Helper()
	public, internal := workflowListen(t), workflowListen(t)
	client, err := controlrelay.NewDirectClient(controlrelay.DirectConfig{Store: database, LeaseDuration: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	runID, err := opaqueid.New(opaqueid.RelayRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := relay.NewController(relay.ControllerConfig{Client: client, Registration: relayv1.RelayRegistration{ProtocolVersion: tunnelv1.Version, RelayServiceId: id, RelayId: id, RelayRunId: runID, RelayAddress: net.JoinHostPort("localhost", fmt.Sprint(public.Addr().(*net.TCPAddr).Port)), InternalRelayAddress: internal.Addr().String(), InternalNetworks: []string{"127.0.0.0/8"}, TlsServerName: "localhost", ConnectionCapacity: 128, StreamCapacity: 128}, RenewalInterval: 200 * time.Millisecond, RetryInterval: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	f.workers.Go(func() { _ = controller.Run(f.ctx) })
	workflowWait(t, 5*time.Second, func() bool { return controller.Lease().RelayLeaseRevision > 0 })
	registry, private := relay.NewRegistry(), relay.NewServiceRegistry()
	t.Cleanup(func() { _ = registry.Close(); _ = private.Close() })
	acceptor, err := relay.NewPublisherAcceptor(relay.PublisherAcceptorConfig{Select: func(service string) (relay.PublisherConnectionController, *relay.Registry, bool) {
		return controller, registry, service == id
	}, Private: &relay.ServicePublisherAcceptor{Select: func(service string) (relay.ServicePublisherTarget, bool) {
		return relay.ServicePublisherTarget{Control: controller, Registry: private}, service == id
	}}})
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := serviceapi.NewBearerSecrets(cliWorkflowClusterSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	forward, err := relay.NewForwardingAcceptor(relay.ForwardingAcceptorConfig{Registry: registry, ServiceRegistry: private, CurrentLease: controller.Lease, ClusterSecrets: secrets, StreamCapacity: 128})
	if err != nil {
		t.Fatal(err)
	}
	f.serve(t, public, func(connection net.Conn) error {
		transport, err := muxsession.AcceptTLSYamux(f.ctx, connection, f.tls, muxsession.TLSYamuxConfig{MaxIncomingStreams: 128})
		if err != nil {
			return err
		}
		return acceptor.Accept(f.ctx, transport)
	})
	f.serve(t, internal, func(connection net.Conn) error {
		transport, err := muxsession.AcceptTLSYamux(f.ctx, connection, f.tls, muxsession.TLSYamuxConfig{MaxIncomingStreams: 128})
		if err != nil {
			return err
		}
		return forward.Accept(f.ctx, transport)
	})
}

func (f *cliWorkflow) ingress(t *testing.T, database *controlstate.Database, id string) {
	t.Helper()
	listener := workflowListen(t)
	client, err := controlingress.NewDirectClient(controlingress.DirectConfig{Store: database, LeaseDuration: 30 * time.Second, RoutingPollInterval: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	runID, err := opaqueid.New(opaqueid.IngressRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	address, name := listener.Addr().String(), "localhost"
	routing := &ingress.RoutingTable{}
	ports := make([]int, 16)
	for index := range ports {
		ports[index] = 20000 + index
	}
	controller, err := ingress.NewController(ingress.ControllerConfig{Client: client, VisitorControl: client, RoutingTable: routing, Registration: ingressv1.IngressRegistration{ProtocolVersion: tunnelv1.Version, IngressId: id, IngressRunId: runID, IngressPoolId: "ingress-a", ServicePorts: ports, ConnectionCapacity: 128, ConnectorAddress: &address, ConnectorTlsServerName: &name}, RenewalInterval: 200 * time.Millisecond, RetryInterval: 25 * time.Millisecond, RoutingWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f.workers.Go(func() { _ = controller.Run(f.ctx) })
	workflowWait(t, 5*time.Second, func() bool { return controller.Ready(time.Now()) })
	// certificates expire with their issuing lease deadline. fetch current
	// material for later connectors after the controller renews that lease.
	getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		lease := controller.Lease()
		ctx, cancel := context.WithTimeout(hello.Context(), 5*time.Second)
		defer cancel()
		material, err := client.GetIngressTransportCertificate(ctx, id, ingressv1.GetIngressTransportCertificateJSONRequestBody{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision})
		if err != nil {
			return nil, err
		}
		certificate, err := tls.X509KeyPair([]byte(material.Trust.CertificatePem), []byte(material.PrivateKeyPem))
		return &certificate, err
	}
	forwarder, err := ingress.NewForwarder(ingress.ForwarderConfig{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ClusterSecret: cliWorkflowClusterSecret})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarder.Close() })
	connector, err := ingress.NewConnector(ingress.ConnectorConfig{Hostname: name, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: getCertificate}, Control: client, DirectControl: client, Forwarder: forwarder, Routing: &ingress.ServiceRoutingTable{}, CurrentLease: controller.Lease})
	if err != nil {
		t.Fatal(err)
	}
	if f.directConnector == nil {
		f.directConnector = connector
	}
	t.Cleanup(func() { _ = connector.Close() })
	f.serve(t, listener, func(connection net.Conn) error {
		return connector.Accept(f.ctx, connection, netip.MustParseAddrPort(connection.RemoteAddr().String()), netip.MustParseAddrPort(connection.LocalAddr().String()))
	})
	publicListener := workflowListen(t)
	if f.publicAddress == "" {
		f.publicAddress = publicListener.Addr().String()
	}
	publicServer, err := ingress.New(publicListener, ingress.Config{MaxConnections: 128, LookupPool: func(host string) ([]ingress.PublicURL, ingress.LookupReason) {
		return controller.LookupPublicURLs(host, forwarder, time.Now())
	}})
	if err != nil {
		t.Fatal(err)
	}
	context.AfterFunc(f.ctx, func() { _ = publicListener.Close() })
	t.Cleanup(func() {
		_ = publicListener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = publicServer.Drain(ctx)
	})
	f.workers.Go(func() { _ = publicServer.Serve() })
}

// the local CA and DNS boundary are test infrastructure. control still owns
// real CSR work leases, installation acknowledgements, DNS state and readiness.
func (f *cliWorkflow) certificateWork(t *testing.T, database *controlstate.Database) {
	for f.ctx.Err() == nil {
		if f.certificateWorkPaused.Load() {
			select {
			case <-f.ctx.Done():
				return
			case <-time.After(25 * time.Millisecond):
				continue
			}
		}
		now := time.Now().UTC()
		work, found, err := database.ClaimACMEOrderWork(f.ctx, "cli-ca", now, time.Minute)
		if err != nil && f.ctx.Err() == nil {
			t.Errorf("local CA claim: %v", err)
			return
		}
		if found {
			request, err := x509.ParseCertificateRequest(work.CSRDER)
			if err != nil || request.CheckSignature() != nil {
				t.Error("local CA received an invalid publisher CSR")
				return
			}
			serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
			if err != nil {
				t.Error(err)
				return
			}
			before, after := now.Add(-time.Minute).Truncate(time.Second), now.Add(30*time.Minute).Truncate(time.Second)
			leaf := &x509.Certificate{SerialNumber: serial, Subject: request.Subject, DNSNames: request.DNSNames, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
			der, err := x509.CreateCertificate(rand.Reader, leaf, f.issuer, request.PublicKey, f.issuerKey)
			if err != nil {
				t.Error(err)
				return
			}
			work.CertificatePEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw})...)
			work.State, work.NotBefore, work.NotAfter, work.AvailableAt = "waiting_for_install", &before, &after, now
			if _, err := database.SaveACMEOrderWork(f.ctx, work, now); err != nil && f.ctx.Err() == nil {
				t.Errorf("local CA completion: %v", err)
				return
			}
		}
		select {
		case <-f.ctx.Done():
			return
		case <-time.After(25 * time.Millisecond):
		}
	}
}
