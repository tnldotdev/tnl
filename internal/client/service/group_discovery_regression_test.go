package publisherjob

import (
	"context"
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

	grouppublisher "github.com/tnldotdev/tnl/internal/publisher/group"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	targetdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type groupAWSRoundTrip func(*http.Request) (*http.Response, error)

func (f groupAWSRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func routeGroupAWS(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	previous := http.DefaultTransport
	http.DefaultTransport = groupAWSRoundTrip(func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		copy.Host = r.URL.Host
		copy.URL.Scheme, copy.URL.Host = "https", strings.TrimPrefix(server.URL, "https://")
		return server.Client().Transport.RoundTrip(copy)
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func discoveryRegressionRunner(t *testing.T, role bool) (GroupRunner, string) {
	t.Helper()
	job, _, key := kindFixture(t, KindGroup)
	value, err := credentialfile.NewGroup(job.Server, job.GroupInstance, *job.GroupMember, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "aws.json")
	if err := os.WriteFile(path, []byte(`{"access_key_id":"SELECTED_KEY","secret_access_key":"selected-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	aws := &AWSBinding{CredentialsFile: path}
	if role {
		aws.RoleARN, aws.RoleRegion = "arn:aws:iam::123456789012:role/discovery", "us-east-1"
	}
	runner, _, err := ScopedGroupRunner(value, &GroupBinding{Version: 1, Scope: ScopeForGroup(value), AWS: aws, Discovery: []DiscoveryBinding{{Type: "rds", Region: "us-east-1", Instance: "database", Protocol: "postgres", Account: "123456789012"}}}, nil, NewOperationLimiter(1))
	if err != nil {
		t.Fatal(err)
	}
	return runner, path
}

func assignmentRegressionRequest(t *testing.T) targetdiscovery.Request {
	t.Helper()
	r, err := grouppublisher.AssignmentDiscovery(controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.PrivateServiceProtocol("postgres")), Publisher: new("cloud"), TargetDiscovery: &controlv1.ProjectTargetDiscovery{Type: controlv1.Rds, Region: "us-east-1", Instance: new("database")}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func serveRegressionAWS(w http.ResponseWriter, r *http.Request, account string) {
	_, _ = io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "text/xml")
	if strings.HasPrefix(r.Host, "sts.") {
		_, _ = io.WriteString(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>`+account+`</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
	} else {
		_, _ = io.WriteString(w, `<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance><DBInstanceIdentifier>database</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:123456789012:db:database</DBInstanceArn><DbiResourceId>db-immutable</DbiResourceId><Engine>postgres</Engine><CACertificateIdentifier>rds-ca-rsa2048-g1</CACertificateIdentifier><DBInstanceStatus>available</DBInstanceStatus><Endpoint><Address>database.example.test</Address><Port>5432</Port></Endpoint></DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`)
	}
}

func TestScopedGroupAssignmentAppliesBindingAccountAtAWSBoundary(t *testing.T) {
	runner, _ := discoveryRegressionRunner(t, false)
	var calls atomic.Int32
	account := "123456789012"
	routeGroupAWS(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=SELECTED_KEY/") {
			t.Error("unselected signer")
		}
		serveRegressionAWS(w, r, account)
	})
	request := assignmentRegressionRequest(t)
	if request.Account != "" {
		t.Fatal("assignment unexpectedly owns account constraint")
	}
	if _, err := runner.Discovery.Discover(t.Context(), request); err != nil {
		t.Fatal("valid assignment denied by local account constraint", err)
	}
	if calls.Load() != 2 {
		t.Fatal("did not cross actual scoped STS/RDS SDK boundary", calls.Load())
	}
	account = "210987654321"
	if _, err := runner.Discovery.Discover(t.Context(), request); targetdiscovery.ErrorKind(err) != targetdiscovery.Metadata || calls.Load() != 3 {
		t.Fatal("credential account constraint was not enforced before Describe", err)
	}
}

func TestScopedGroupSignerPreservesSelectedCredentialAuthentication(t *testing.T) {
	for _, mode := range []string{"missing", "unsafe", "expired"} {
		t.Run(mode, func(t *testing.T) {
			runner, path := discoveryRegressionRunner(t, false)
			var calls atomic.Int32
			routeGroupAWS(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); serveRegressionAWS(w, r, "123456789012") })
			resolver, err := targetdiscovery.New(runner.Discovery, targetdiscovery.Options{TTL: time.Millisecond, MaxStaleness: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			defer resolver.Close()
			request := assignmentRegressionRequest(t)
			if _, err := resolver.Resolve(t.Context(), request); err != nil {
				t.Fatal("seed last-success through the real signer", err)
			}
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "unsafe":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if err := os.WriteFile(path, []byte(`{"access_key_id":"SELECTED_KEY","secret_access_key":"selected-secret","expires_at":"2000-01-01T00:00:00Z"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(2 * time.Millisecond)
			_, err = resolver.Resolve(t.Context(), request)
			if targetdiscovery.ErrorKind(err) != targetdiscovery.Authentication || !blockedFailure(err) || !errors.Is(err, ErrUnsafeState) || calls.Load() != 2 {
				t.Fatal("SDK signer erased auth failure", err)
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "selected-secret") {
				t.Fatal("credential cause leaked into diagnostic")
			}
		})
	}
}

func TestScopedGroupAssumeRoleCancellationJoinsProviderBeforeLimiterRelease(t *testing.T) {
	runner, _ := discoveryRegressionRunner(t, true)
	started, stopped, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	routeGroupAWS(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		close(started)
		defer close(stopped)
		select {
		case <-r.Context().Done():
		case <-release:
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`)
	})
	resolver, err := targetdiscovery.New(runner.Discovery, targetdiscovery.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := assignmentRegressionRequest(t)
	r.Account = "123456789012"
	done := make(chan struct{})
	go func() { defer close(done); _, _ = resolver.Resolve(context.Background(), r) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		resolver.Close()
		t.Fatal("AssumeRole did not start")
	}
	resolver.Close()
	<-done
	select {
	case <-stopped:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("resolver joined and released its provider slot while detached AssumeRole was still running")
	}
}
