package installed

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
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// DeploymentScope binds operator-owned dependencies to immutable authority, never
// to a friendly deployment/project name or a credential file's location.
type DeploymentScope struct {
	Server     string `json:"control_url"`
	Team       string `json:"team_id"`
	Deployment string `json:"deployment_id"`
	Publisher  string `json:"publisher_identity_id"`
}

func ScopeForDeployment(value credentialfile.DeploymentFile) DeploymentScope {
	return DeploymentScope{value.ControlURL, value.Member.TeamId, value.Member.DeploymentId, value.Member.PublisherIdentityId}
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

func (b DiscoveryBinding) request() publisherdiscovery.Request {
	return publisherdiscovery.Request{Type: b.Type, Region: b.Region, Cluster: b.Cluster, Instance: b.Instance, Endpoint: b.Endpoint, Protocol: b.Protocol, Account: b.Account}
}

type DeploymentBinding struct {
	Version     int                                  `json:"version"`
	Scope       DeploymentScope                      `json:"identity"`
	ServerCAPEM string                               `json:"server_ca_pem,omitempty"`
	Discovery   []DiscoveryBinding                   `json:"discovery,omitempty"`
	AWS         *AWSBinding                          `json:"aws,omitempty"`
	Deployment  *controlv1.PublisherDeploymentReport `json:"deployment,omitempty"`
}

func (DeploymentBinding) String() string   { return "deployment local binding" }
func (DeploymentBinding) GoString() string { return "deployment local binding" }

// ReadDeploymentBinding accepts bounded, private operator input. identity documents
// remain identity-only; this file contains local permissions and source paths.
func ReadDeploymentBinding(path string) (DeploymentBinding, error) {
	var binding DeploymentBinding
	if err := readLocalJSON(path, 256<<10, &binding); err != nil {
		return binding, err
	}
	if err := binding.Validate(); err != nil {
		return DeploymentBinding{}, err
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

func (b DeploymentBinding) Validate() error {
	canonical, err := clientstate.CanonicalServer(b.Scope.Server)
	if err != nil || canonical != b.Scope.Server || b.Version != 1 || b.Scope.Team == "" || b.Scope.Deployment == "" || b.Scope.Publisher == "" || ValidateTrust([]byte(b.ServerCAPEM)) != nil || len(b.Discovery) > 128 || publisherprovenance.Validate(b.Deployment) != nil {
		return ErrScope
	}
	requests := map[publisherdiscovery.Request]bool{}
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

// ScopedDeploymentRunner snapshots discovery permissions before
// workers start. AWS credentials refresh only from the selected private file;
// the SDK default config loader and process AWS environment are never consulted.
func ScopedDeploymentRunner(value credentialfile.DeploymentFile, binding *DeploymentBinding, startup, providers *OperationLimiter) (DeploymentRunner, []byte, error) {
	private, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.DeploymentName, value.Instance)
	if err != nil {
		return DeploymentRunner{}, nil, errors.Join(ErrScope, err)
	}
	b := DeploymentBinding{Version: 1, Scope: ScopeForDeployment(value)}
	if binding != nil {
		b = *binding
	}
	if b.Validate() != nil || b.Scope != ScopeForDeployment(value) || b.Deployment != nil && b.Deployment.Instance != value.Instance {
		return DeploymentRunner{}, nil, ErrScope
	}
	var selected *AWSBinding
	if b.AWS != nil {
		copy := *b.AWS
		selected = &copy
	}
	discovery := &scopedDeploymentDiscovery{allowed: map[publisherdiscovery.Request]string{}, limiter: providers, provider: publisherdiscovery.AWS{Load: func(ctx context.Context, region string) (publisherdiscovery.Clients, error) {
		if selected == nil {
			return publisherdiscovery.Clients{}, &publisherdiscovery.Error{Kind: publisherdiscovery.Permission}
		}
		var credentials aws.CredentialsProvider = fileCredentials{path: selected.CredentialsFile}
		if selected.RoleARN != "" {
			cfg := scopedAWSConfig(selected.RoleRegion, credentials)
			// this provider belongs to one bounded discovery call. the SDK cache
			// detaches refresh cancellation, so do not wrap it in CredentialsCache.
			credentials = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), selected.RoleARN)
		}
		cfg := scopedAWSConfig(region, credentials)
		return publisherdiscovery.Clients{EKS: eks.NewFromConfig(cfg), RDS: rds.NewFromConfig(cfg), Caller: sts.NewFromConfig(cfg)}, nil
	}}}
	for _, request := range b.Discovery {
		key, _ := request.request().Normalize()
		account := key.Account
		key.Account = ""
		discovery.allowed[key] = account
	}
	return DeploymentRunner{Discovery: discovery, Deployment: b.Deployment, Startup: startup, scope: &deploymentRunnerScope{identity: b.Scope, project: value.Member.ProjectKey, instance: value.Instance, keyID: value.Member.KeyId, public: private.Public().(ed25519.PublicKey)}}, []byte(b.ServerCAPEM), nil
}

type scopedDeploymentDiscovery struct {
	allowed  map[publisherdiscovery.Request]string
	provider publisherdiscovery.Provider
	limiter  *OperationLimiter
}

func (p *scopedDeploymentDiscovery) Discover(ctx context.Context, request publisherdiscovery.Request) (publisherdiscovery.ResolvedTarget, error) {
	key, err := request.Normalize()
	if err != nil {
		return publisherdiscovery.ResolvedTarget{}, err
	}
	requestedAccount := key.Account
	key.Account = ""
	account, allowed := p.allowed[key]
	if !allowed || requestedAccount != "" && account != "" && requestedAccount != account {
		return publisherdiscovery.ResolvedTarget{}, &publisherdiscovery.Error{Kind: publisherdiscovery.Permission}
	}
	key.Account = account
	if key.Account == "" {
		key.Account = requestedAccount
	}
	release, err := p.limiter.Acquire(ctx)
	if err != nil {
		return publisherdiscovery.ResolvedTarget{}, err
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
		return aws.Credentials{}, publisherdiscovery.CredentialError(ErrUnsafeState)
	}
	return aws.Credentials{AccessKeyID: value.AccessKeyID, SecretAccessKey: value.SecretAccessKey, SessionToken: value.SessionToken, CanExpire: !value.ExpiresAt.IsZero(), Expires: value.ExpiresAt, Source: "deployment binding"}, nil
}

func scopedAWSConfig(region string, credentials aws.CredentialsProvider) aws.Config {
	return aws.Config{Region: region, Credentials: credentials, Logger: logging.Nop{}, HTTPClient: &http.Client{Transport: boundedDeploymentAWS{}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Retryer: func() aws.Retryer { return retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 2 }) }}
}

type boundedDeploymentAWS struct{}

func (boundedDeploymentAWS) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(r)
	if response != nil && response.Body != nil {
		response.Body = &deploymentAWSBody{ReadCloser: response.Body, left: 1 << 20}
	}
	return response, err
}

type deploymentAWSBody struct {
	io.ReadCloser
	left int64
}

func (b *deploymentAWSBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, &publisherdiscovery.Error{Kind: publisherdiscovery.Invalid}
	}
	return n, err
}
