package publisherjob

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/internal/targetdiscovery"
)

func TestScopedGroupDiscoveryDeniesAmbientAndOtherTeamBinding(t *testing.T) {
	jobA, _, keyA := kindFixture(t, KindGroup)
	jobB, _, keyB := kindFixture(t, KindGroup)
	jobB.GroupMember.TeamId = "other-team"
	jobB.GroupMember.GroupName = jobA.GroupMember.GroupName
	jobB.GroupMember.ProjectKey = jobA.GroupMember.ProjectKey
	jobB.GroupInstance = jobA.GroupInstance
	a, err := credentialfile.NewGroup(jobA.Server, jobA.GroupInstance, *jobA.GroupMember, keyA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := credentialfile.NewGroup(jobB.Server, jobB.GroupInstance, *jobB.GroupMember, keyB)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	makeRunner := func(value credentialfile.GroupFile) GroupRunner {
		runner, _, err := ScopedGroupRunner(value, &GroupBinding{Version: 1, Scope: ScopeForGroup(value)}, nil, NewOperationLimiter(2))
		if err != nil {
			t.Fatal(err)
		}
		return runner
	}
	runners := []GroupRunner{makeRunner(a), makeRunner(b)}
	for _, runner := range runners {
		_, err = runner.Discovery.Discover(t.Context(), targetdiscovery.Request{Type: "eks", Region: "us-east-1", Cluster: "same", Protocol: "kubernetes"})
		if targetdiscovery.ErrorKind(err) != targetdiscovery.Permission || !blockedFailure(err) {
			t.Fatal("ambient AWS discovery was not blocked", err)
		}
	}
	if _, _, err := ScopedGroupRunner(b, &GroupBinding{Version: 1, Scope: ScopeForGroup(a)}, nil, nil); !errors.Is(err, ErrScope) {
		t.Fatal("another team's binding accepted", err)
	}
	deny, _, err := ScopedGroupRunner(a, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deny.Discovery.Discover(t.Context(), targetdiscovery.Request{Type: "eks", Region: "us-east-1", Cluster: "same", Protocol: "kubernetes"}); targetdiscovery.ErrorKind(err) != targetdiscovery.Permission {
		t.Fatal("absent binding used ambient discovery", err)
	}
}

func TestScopedGroupAWSSignsWithSelectedFileAndDeniesOtherGroup(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AMBIENT_KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	t.Setenv("AWS_ENDPOINT_URL_EKS", "https://ambient.invalid")
	job, _, key := kindFixture(t, KindGroup)
	value, err := credentialfile.NewGroup(job.Server, job.GroupInstance, *job.GroupMember, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "aws.json")
	if err := os.WriteFile(path, []byte(`{"access_key_id":"GROUP_A_KEY","secret_access_key":"group-a-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	runner, _, err := ScopedGroupRunner(value, &GroupBinding{Version: 1, Scope: ScopeForGroup(value), AWS: &AWSBinding{CredentialsFile: path}}, nil, NewOperationLimiter(1))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=GROUP_A_KEY/") || strings.Contains(r.Header.Get("Authorization"), "AMBIENT_KEY") {
			t.Error("AWS signer did not use the explicitly selected credentials")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"cluster":{"name":"production"}}`)
	}))
	defer server.Close()
	discovery := runner.Discovery.(*scopedGroupDiscovery)
	load := discovery.provider.(targetdiscovery.AWS).Load
	// only the test's transport destination changes. the production constructor
	// supplies the actual scoped SDK client and its signing credential provider.
	clients, err := load(t.Context(), "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	client := clients.EKS.(*eks.Client)
	got, err := client.DescribeCluster(t.Context(), &eks.DescribeClusterInput{Name: new("production")}, func(o *eks.Options) { o.BaseEndpoint = &server.URL; o.HTTPClient = server.Client() })
	if err != nil || got.Cluster == nil || *got.Cluster.Name != "production" || calls.Load() != 1 {
		t.Fatal("scoped AWS discovery signer failed", err)
	}
	denied, _, err := ScopedGroupRunner(value, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	deniedLoad := denied.Discovery.(*scopedGroupDiscovery).provider.(targetdiscovery.AWS).Load
	if _, err := deniedLoad(t.Context(), "us-east-1"); targetdiscovery.ErrorKind(err) != targetdiscovery.Permission || calls.Load() != 1 {
		t.Fatal("unbound group borrowed AWS credentials")
	}
}

type discoveryCall func(context.Context, targetdiscovery.Request) (targetdiscovery.ResolvedTarget, error)

func (f discoveryCall) Discover(ctx context.Context, r targetdiscovery.Request) (targetdiscovery.ResolvedTarget, error) {
	return f(ctx, r)
}

func TestScopedGroupDiscoveryRequiresExactPermissionBeforeProvider(t *testing.T) {
	request := targetdiscovery.Request{Type: "eks", Region: "us-east-1", Cluster: "production", Protocol: "kubernetes", Account: "123456789012"}
	var calls atomic.Int32
	provider := discoveryCall(func(_ context.Context, r targetdiscovery.Request) (targetdiscovery.ResolvedTarget, error) {
		calls.Add(1)
		return targetdiscovery.ResolvedTarget{ResourceID: r.Account}, nil
	})
	selector := request
	selector.Account = ""
	a := scopedGroupDiscovery{allowed: map[targetdiscovery.Request]string{selector: request.Account}, provider: provider, limiter: NewOperationLimiter(1)}
	b := scopedGroupDiscovery{allowed: map[targetdiscovery.Request]string{}, provider: provider, limiter: a.limiter}
	if _, err := a.Discover(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Discover(t.Context(), request); targetdiscovery.ErrorKind(err) != targetdiscovery.Permission {
		t.Fatal("another group's selector was not denied", err)
	}
	request.Account = "210987654321"
	if _, err := a.Discover(t.Context(), request); targetdiscovery.ErrorKind(err) != targetdiscovery.Permission || calls.Load() != 1 {
		t.Fatal("discovery broadened an exact account permission", err)
	}
}

func TestScopedGroupAWSCredentialsHaveNoFallback(t *testing.T) {
	credentials := filepath.Join(t.TempDir(), "aws.json")
	if err := os.WriteFile(credentials, []byte(`{"access_key_id":"selected-key","secret_access_key":"selected-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	provider := fileCredentials{credentials}
	for _, want := range []string{"selected-key", "rotated-key"} {
		data, _ := json.Marshal(map[string]string{"access_key_id": want, "secret_access_key": "selected-secret"})
		if err := os.WriteFile(credentials, data, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := provider.Retrieve(t.Context())
		if err != nil || got.AccessKeyID != want {
			t.Fatal("credential file refresh", err)
		}
	}
	if err := os.Remove(credentials); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient")
	if _, err := provider.Retrieve(t.Context()); err == nil {
		t.Fatal("missing scoped credentials fell back")
	}
}

func TestOperationLimiterBoundsAndJoinsCanceledWaiters(t *testing.T) {
	limiter := NewOperationLimiter(2)
	ctx, cancel := context.WithCancel(t.Context())
	var active, peak atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			release, err := limiter.Acquire(ctx)
			if err != nil {
				return
			}
			defer release()
			count := active.Add(1)
			for previous := peak.Load(); count > previous; previous = peak.Load() {
				if peak.CompareAndSwap(previous, count) {
					break
				}
			}
			<-ctx.Done()
			active.Add(-1)
		})
	}
	deadline := time.Now().Add(time.Second)
	for peak.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	wg.Wait()
	if peak.Load() != 2 || active.Load() != 0 {
		t.Fatal("provider concurrency was not bounded/joined")
	}
	release, err := limiter.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	release()
	release()
}

func TestScopedGroupRunnerRejectsWrongJobBeforeAnyControlWork(t *testing.T) {
	job, _, key := kindFixture(t, KindGroup)
	value, err := credentialfile.NewGroup(job.Server, job.GroupInstance, *job.GroupMember, key)
	if err != nil {
		t.Fatal(err)
	}
	runner, _, err := ScopedGroupRunner(value, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	registry := testRegistry(t)
	profile, err := registry.Profile(t.Context(), job.Server)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Job){
		func(j *Job) { j.Server = "https://other.example" },
		func(j *Job) { j.GroupMember.TeamId = "other-team" },
		func(j *Job) { j.GroupInstance = "other-instance" },
		func(j *Job) { j.GroupMember.ProjectKey = "other-project" },
		func(j *Job) { other, _, _ := kindFixture(t, KindGroup); j.GroupMember.KeyId = other.GroupMember.KeyId },
	} {
		other := job
		member := *job.GroupMember
		other.GroupMember = &member
		change(&other)
		if err := runner.Serve(t.Context(), other, profile, key, nil); !errors.Is(err, ErrScope) {
			t.Fatal("runner accepted dependencies for another job", err)
		}
	}
	_, _, otherKey := kindFixture(t, KindGroup)
	if err := runner.Serve(t.Context(), job, profile, otherKey, nil); !errors.Is(err, ErrScope) {
		t.Fatal("runner accepted another signing key", err)
	}
}

func TestScopedGroupBindingRejectsConflictingAccountConstraints(t *testing.T) {
	job, _, key := kindFixture(t, KindGroup)
	value, err := credentialfile.NewGroup(job.Server, job.GroupInstance, *job.GroupMember, key)
	if err != nil {
		t.Fatal(err)
	}
	b := GroupBinding{Version: 1, Scope: ScopeForGroup(value), AWS: &AWSBinding{CredentialsFile: "/run/secrets/aws.json"}, Discovery: []DiscoveryBinding{{Type: "eks", Region: "us-east-1", Cluster: "production", Protocol: "kubernetes", Account: "123456789012"}, {Type: "eks", Region: "us-east-1", Cluster: "production", Protocol: "kubernetes", Account: "210987654321"}}}
	if err := b.Validate(); !errors.Is(err, ErrScope) {
		t.Fatal("same selector admitted ambiguous accounts", err)
	}
}
