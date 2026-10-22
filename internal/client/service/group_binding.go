package publisherjob

import (
	"context"
	"crypto/ed25519"
	json "encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	targetdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// GroupScope binds operator-owned dependencies to immutable authority, never
// to a friendly group/project name or a credential file's location.
type GroupScope struct {
	Server    string `json:"control_url"`
	Team      string `json:"team_id"`
	Group     string `json:"group_id"`
	Publisher string `json:"publisher_identity_id"`
}

func ScopeForGroup(value credentialfile.GroupFile) GroupScope {
	return GroupScope{value.ControlURL, value.Member.TeamId, value.Member.GroupId, value.Member.PublisherIdentityId}
}

type AWSBinding struct {
	CredentialsFile string `json:"credentials_file"`
	RoleARN         string `json:"role_arn,omitempty"`
	RoleRegion      string `json:"role_region,omitempty"`
}

type DiscoveryBinding struct {
	Type     string `json:"type"`
	Region   string `json:"region"`
	Cluster  string `json:"cluster,omitempty"`
	Instance string `json:"instance,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Protocol string `json:"protocol"`
	Account  string `json:"account,omitempty"`
}

func (b DiscoveryBinding) request() targetdiscovery.Request {
	return targetdiscovery.Request{Type: b.Type, Region: b.Region, Cluster: b.Cluster, Instance: b.Instance, Endpoint: b.Endpoint, Protocol: b.Protocol, Account: b.Account}
}

type GroupBinding struct {
	Version     int                                  `json:"version"`
	Scope       GroupScope                           `json:"identity"`
	ServerCAPEM string                               `json:"server_ca_pem,omitempty"`
	Discovery   []DiscoveryBinding                   `json:"discovery,omitempty"`
	AWS         *AWSBinding                          `json:"aws,omitempty"`
	Deployment  *controlv1.PublisherDeploymentReport `json:"deployment,omitempty"`
}

func (GroupBinding) String() string   { return "publisher group local binding" }
func (GroupBinding) GoString() string { return "publisher group local binding" }

// ReadGroupBinding accepts bounded, private operator input. identity documents
// remain identity-only; this file contains local permissions and source paths.
func ReadGroupBinding(path string) (GroupBinding, error) {
	var binding GroupBinding
	if err := readLocalJSON(path, 256<<10, &binding); err != nil {
		return binding, err
	}
	if err := binding.Validate(); err != nil {
		return GroupBinding{}, err
	}
	return binding, nil
}

func readLocalJSON(path string, limit int64, out any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrScope
	}
	f, err := clientstate.OpenPrivateFile(path)
	if err != nil {
		return ErrUnsafeState
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	defer clear(data)
	if err != nil || int64(len(data)) > limit || json.Unmarshal(data, out, json.RejectUnknownMembers(true)) != nil {
		return ErrScope
	}
	return nil
}

var localRoleARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]{1,512}$`)
var localAWSRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

func (b GroupBinding) Validate() error {
	canonical, err := clientstate.CanonicalServer(b.Scope.Server)
	if err != nil || canonical != b.Scope.Server || b.Version != 1 || b.Scope.Team == "" || b.Scope.Group == "" || b.Scope.Publisher == "" || ValidateTrust([]byte(b.ServerCAPEM)) != nil || len(b.Discovery) > 128 || publisherprovenance.Validate(b.Deployment) != nil {
		return ErrScope
	}
	requests := map[targetdiscovery.Request]bool{}
	for _, request := range b.Discovery {
		key, err := request.request().Normalize()
		// account is an operator constraint, not part of control's selector.
		key.Account = ""
		if err != nil || requests[key] || b.AWS == nil {
			return ErrScope
		}
		requests[key] = true
	}
	if b.AWS != nil {
		a := b.AWS
		if !filepath.IsAbs(a.CredentialsFile) || filepath.Clean(a.CredentialsFile) != a.CredentialsFile || len(a.CredentialsFile) > 4096 || strings.ContainsAny(a.CredentialsFile, "\x00\r\n") {
			return ErrScope
		}
		if a.RoleARN != "" {
			if !localRoleARN.MatchString(a.RoleARN) || len(a.RoleRegion) > 32 || !localAWSRegion.MatchString(a.RoleRegion) {
				return ErrScope
			}
		} else if a.RoleRegion != "" {
			return ErrScope
		}
	}
	return nil
}

// ScopedGroupRunner snapshots discovery permissions before
// workers start. AWS credentials refresh only from the selected private file;
// the SDK default config loader and process AWS environment are never consulted.
func ScopedGroupRunner(value credentialfile.GroupFile, binding *GroupBinding, startup, providers *OperationLimiter) (GroupRunner, []byte, error) {
	private, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.GroupName, value.Instance)
	if err != nil {
		return GroupRunner{}, nil, errors.Join(ErrScope, err)
	}
	b := GroupBinding{Version: 1, Scope: ScopeForGroup(value)}
	if binding != nil {
		b = *binding
	}
	if b.Validate() != nil || b.Scope != ScopeForGroup(value) || b.Deployment != nil && b.Deployment.Instance != value.Instance {
		return GroupRunner{}, nil, ErrScope
	}
	var selected *AWSBinding
	if b.AWS != nil {
		copy := *b.AWS
		selected = &copy
	}
	discovery := &scopedGroupDiscovery{allowed: map[targetdiscovery.Request]string{}, limiter: providers, provider: targetdiscovery.AWS{Load: func(ctx context.Context, region string) (targetdiscovery.Clients, error) {
		if selected == nil {
			return targetdiscovery.Clients{}, &targetdiscovery.Error{Kind: targetdiscovery.Permission}
		}
		var credentials aws.CredentialsProvider = fileCredentials{path: selected.CredentialsFile}
		if selected.RoleARN != "" {
			cfg := scopedAWSConfig(selected.RoleRegion, credentials)
			// this provider belongs to one bounded discovery call. the SDK cache
			// detaches refresh cancellation, so do not wrap it in CredentialsCache.
			credentials = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), selected.RoleARN)
		}
		cfg := scopedAWSConfig(region, credentials)
		return targetdiscovery.Clients{EKS: eks.NewFromConfig(cfg), RDS: rds.NewFromConfig(cfg), Caller: sts.NewFromConfig(cfg)}, nil
	}}}
	for _, request := range b.Discovery {
		key, _ := request.request().Normalize()
		account := key.Account
		key.Account = ""
		discovery.allowed[key] = account
	}
	return GroupRunner{Discovery: discovery, Deployment: b.Deployment, Startup: startup, scope: &groupRunnerScope{identity: b.Scope, project: value.Member.ProjectKey, instance: value.Instance, keyID: value.Member.KeyId, public: private.Public().(ed25519.PublicKey)}}, []byte(b.ServerCAPEM), nil
}

type scopedGroupDiscovery struct {
	allowed  map[targetdiscovery.Request]string
	provider targetdiscovery.Provider
	limiter  *OperationLimiter
}

func (p *scopedGroupDiscovery) Discover(ctx context.Context, request targetdiscovery.Request) (targetdiscovery.ResolvedTarget, error) {
	key, err := request.Normalize()
	if err != nil {
		return targetdiscovery.ResolvedTarget{}, err
	}
	requestedAccount := key.Account
	key.Account = ""
	account, allowed := p.allowed[key]
	if !allowed || requestedAccount != "" && account != "" && requestedAccount != account {
		return targetdiscovery.ResolvedTarget{}, &targetdiscovery.Error{Kind: targetdiscovery.Permission}
	}
	key.Account = account
	if key.Account == "" {
		key.Account = requestedAccount
	}
	release, err := p.limiter.Acquire(ctx)
	if err != nil {
		return targetdiscovery.ResolvedTarget{}, err
	}
	defer release()
	return p.provider.Discover(ctx, key)
}

type fileCredentials struct{ path string }

func (p fileCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return aws.Credentials{}, context.Cause(ctx)
	}
	var value struct {
		AccessKeyID     string    `json:"access_key_id"`
		SecretAccessKey string    `json:"secret_access_key"`
		SessionToken    string    `json:"session_token,omitempty"`
		ExpiresAt       time.Time `json:"expires_at,omitempty"`
	}
	if readLocalJSON(p.path, 16384, &value) != nil || value.AccessKeyID == "" || value.SecretAccessKey == "" || !value.ExpiresAt.IsZero() && !value.ExpiresAt.After(time.Now()) {
		return aws.Credentials{}, targetdiscovery.CredentialError(ErrUnsafeState)
	}
	return aws.Credentials{AccessKeyID: value.AccessKeyID, SecretAccessKey: value.SecretAccessKey, SessionToken: value.SessionToken, CanExpire: !value.ExpiresAt.IsZero(), Expires: value.ExpiresAt, Source: "publisher group binding"}, nil
}

func scopedAWSConfig(region string, credentials aws.CredentialsProvider) aws.Config {
	return aws.Config{Region: region, Credentials: credentials, Logger: logging.Nop{}, HTTPClient: &http.Client{Transport: boundedGroupAWS{}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Retryer: func() aws.Retryer { return retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 2 }) }}
}

type boundedGroupAWS struct{}

func (boundedGroupAWS) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(r)
	if response != nil && response.Body != nil {
		response.Body = &groupAWSBody{ReadCloser: response.Body, left: 1 << 20}
	}
	return response, err
}

type groupAWSBody struct {
	io.ReadCloser
	left int64
}

func (b *groupAWSBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, &targetdiscovery.Error{Kind: targetdiscovery.Invalid}
	}
	return n, err
}
