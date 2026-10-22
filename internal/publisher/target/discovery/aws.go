package targetdiscovery

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/tnldotdev/tnl/internal/publisher/target/discovery/rdsroots"
)

type EKS interface {
	DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
}
type RDS interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
}
type Caller interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}
type Clients struct {
	EKS    EKS
	RDS    RDS
	Caller Caller
}
type LoadClients func(context.Context, string) (Clients, error)

// Load uses the normal AWS chain, including task roles. selected AWS service
// endpoints cannot be redirected through environment/shared-config overrides.
func Load(ctx context.Context, region string) (Clients, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region), awsconfig.WithRetryMaxAttempts(2))
	if err != nil {
		return Clients{}, discoveryError(Authentication, err)
	}
	cfg.ClientLogMode, cfg.Logger = 0, logging.Nop{}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return Clients{}, discoveryError(Authentication, err)
	}
	cfg.HTTPClient = boundedHTTP{client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	return Clients{
		EKS:    eks.NewFromConfig(cfg, func(o *eks.Options) { o.BaseEndpoint = nil }),
		RDS:    rds.NewFromConfig(cfg, func(o *rds.Options) { o.BaseEndpoint = nil }),
		Caller: sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = nil }),
	}, nil
}

// AWS only describes exact selectors. it does not enumerate resources or read
// Secrets Manager, master user credentials, kube tokens, or database passwords.
type AWS struct{ Load LoadClients }

func (p AWS) Discover(ctx context.Context, request Request) (ResolvedTarget, error) {
	r, err := request.Normalize()
	if err != nil {
		return ResolvedTarget{}, err
	}
	load := p.Load
	if load == nil {
		load = Load
	}
	clients, err := load(ctx, r.Region)
	if err != nil {
		return ResolvedTarget{}, safeAWSError(err)
	}
	if clients.Caller == nil {
		return ResolvedTarget{}, discoveryError(Authentication, nil)
	}
	identity, err := clients.Caller.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return ResolvedTarget{}, safeAWSError(err)
	}
	if identity == nil || !accountPattern.MatchString(aws.ToString(identity.Account)) || r.Account != "" && r.Account != aws.ToString(identity.Account) {
		return ResolvedTarget{}, discoveryError(Metadata, nil)
	}
	r.Account = aws.ToString(identity.Account)
	var target ResolvedTarget
	if r.Type == "eks" {
		target, err = discoverEKS(ctx, clients.EKS, r)
	} else {
		target, err = discoverRDS(ctx, clients.RDS, r)
	}
	if err != nil {
		return ResolvedTarget{}, err
	}
	if _, err = target.Verifier(); err != nil {
		return ResolvedTarget{}, err
	}
	return target, nil
}

func discoverEKS(ctx context.Context, client EKS, r Request) (ResolvedTarget, error) {
	if client == nil {
		return ResolvedTarget{}, discoveryError(Unavailable, nil)
	}
	response, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(r.Cluster)})
	if err != nil {
		return ResolvedTarget{}, safeAWSError(err)
	}
	if response == nil || response.Cluster == nil {
		return ResolvedTarget{}, discoveryError(Metadata, nil)
	}
	c := response.Cluster
	if aws.ToString(c.Name) != r.Cluster || !matchesARN(aws.ToString(c.Arn), r, "eks", "cluster/"+r.Cluster) || c.CreatedAt == nil || c.CreatedAt.IsZero() {
		return ResolvedTarget{}, discoveryError(Metadata, nil)
	}
	if c.Status != "ACTIVE" && c.Status != "UPDATING" {
		return ResolvedTarget{}, discoveryError(NotReady, nil)
	}
	if c.AccessConfig == nil || c.AccessConfig.AuthenticationMode != "API" && c.AccessConfig.AuthenticationMode != "API_AND_CONFIG_MAP" && c.AccessConfig.AuthenticationMode != "CONFIG_MAP" {
		return ResolvedTarget{}, discoveryError(Metadata, nil)
	}
	endpoint := aws.ToString(c.Endpoint)
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 512 || u.Scheme != "https" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" && u.Port() != "443" || !validHostname(u.Hostname()) {
		return ResolvedTarget{}, discoveryError(Metadata, nil)
	}
	if c.CertificateAuthority == nil || c.CertificateAuthority.Data == nil || len(*c.CertificateAuthority.Data) > base64.StdEncoding.EncodedLen(64<<10) {
		return ResolvedTarget{}, discoveryError(Metadata, nil)
	}
	ca, err := base64.StdEncoding.Strict().DecodeString(*c.CertificateAuthority.Data)
	if err != nil || len(ca) > 64<<10 {
		return ResolvedTarget{}, discoveryError(Metadata, err)
	}
	// EKS ARN/name can be reused. creation time is part of the immutable pin.
	return ResolvedTarget{Address: net.JoinHostPort(u.Hostname(), "443"), ServerName: u.Hostname(), CA: string(ca), CADigest: digest(string(ca)), ARN: *c.Arn, ResourceID: c.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z"), Protocol: r.Protocol}, nil
}

func discoverRDS(ctx context.Context, client RDS, r Request) (ResolvedTarget, error) {
	if client == nil {
		return ResolvedTarget{}, discoveryError(Unavailable, nil)
	}
	var host, resourceARN, id, engine, caID, status string
	var port int32
	if r.Instance != "" {
		out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{DBInstanceIdentifier: aws.String(r.Instance)})
		if err != nil {
			return ResolvedTarget{}, safeAWSError(err)
		}
		if out == nil || len(out.DBInstances) != 1 || out.Marker != nil && *out.Marker != "" {
			return ResolvedTarget{}, discoveryError(Metadata, nil)
		}
		db := out.DBInstances[0]
		if aws.ToString(db.DBInstanceIdentifier) != r.Instance || db.Endpoint == nil {
			return ResolvedTarget{}, discoveryError(Metadata, nil)
		}
		host, port = aws.ToString(db.Endpoint.Address), aws.ToInt32(db.Endpoint.Port)
		resourceARN, id, engine, caID, status = aws.ToString(db.DBInstanceArn), aws.ToString(db.DbiResourceId), aws.ToString(db.Engine), aws.ToString(db.CACertificateIdentifier), aws.ToString(db.DBInstanceStatus)
		if !matchesARN(resourceARN, r, "rds", "db:"+r.Instance) || caID == "" {
			return ResolvedTarget{}, discoveryError(Metadata, nil)
		}
	} else {
		out, err := client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{DBClusterIdentifier: aws.String(r.Cluster)})
		if err != nil {
			return ResolvedTarget{}, safeAWSError(err)
		}
		if out == nil || len(out.DBClusters) != 1 || out.Marker != nil && *out.Marker != "" {
			return ResolvedTarget{}, discoveryError(Metadata, nil)
		}
		db := out.DBClusters[0]
		if aws.ToString(db.DBClusterIdentifier) != r.Cluster {
			return ResolvedTarget{}, discoveryError(Metadata, nil)
		}
		host, port = aws.ToString(db.Endpoint), aws.ToInt32(db.Port)
		if r.Endpoint == "reader" {
			host = aws.ToString(db.ReaderEndpoint)
		}
		resourceARN, id, engine, status = aws.ToString(db.DBClusterArn), aws.ToString(db.DbClusterResourceId), aws.ToString(db.Engine), aws.ToString(db.Status)
		if db.CertificateDetails != nil {
			caID = aws.ToString(db.CertificateDetails.CAIdentifier)
		}
		if !matchesARN(resourceARN, r, "rds", "cluster:"+r.Cluster) {
			return ResolvedTarget{}, discoveryError(Metadata, nil)
		}
	}
	if !resourcePattern.MatchString(id) || !validHostname(host) || port < 1 || port > 65535 || len(caID) > 128 {
		return ResolvedTarget{}, discoveryError(Metadata, nil)
	}
	if r.Protocol == "postgres" && engine != "postgres" && engine != "aurora-postgresql" || r.Protocol == "mysql" && engine != "mysql" && engine != "aurora-mysql" {
		return ResolvedTarget{}, discoveryError(Metadata, nil)
	}
	if status != "available" {
		return ResolvedTarget{}, discoveryError(NotReady, nil)
	}
	ca, err := rdsroots.Bundle(r.Region)
	if err != nil {
		return ResolvedTarget{}, discoveryError(Metadata, err)
	}
	return ResolvedTarget{Address: net.JoinHostPort(host, strconv.Itoa(int(port))), ServerName: host, CA: ca, CADigest: digest(ca), ARN: resourceARN, ResourceID: id, CAIdentifier: caID, Protocol: r.Protocol}, nil
}

func matchesARN(value string, r Request, service, resource string) bool {
	if len(value) > 512 {
		return false
	}
	a, err := arn.Parse(value)
	partition := "aws"
	if strings.HasPrefix(r.Region, "cn-") {
		partition = "aws-cn"
	} else if strings.HasPrefix(r.Region, "us-gov-") {
		partition = "aws-us-gov"
	}
	return err == nil && a.Partition == partition && a.Service == service && a.Region == r.Region && a.AccountID == r.Account && a.Resource == resource
}

// metadata responses are bounded before the SDK unmarshals them. the context
// bounds slow readers; oversized responses cannot fill publisher memory.
type boundedHTTP struct{ client aws.HTTPClient }

func (c boundedHTTP) Do(request *http.Request) (*http.Response, error) {
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > 1<<20 {
		response.Body.Close()
		return nil, discoveryError(Metadata, nil)
	}
	response.Body = &boundedBody{ReadCloser: response.Body, left: 1 << 20}
	return response, nil
}

type boundedBody struct {
	io.ReadCloser
	left int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, discoveryError(Metadata, nil)
	}
	return n, err
}

func safeAWSError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var owned *Error
	if errors.As(err, &owned) {
		return discoveryError(owned.Kind, err)
	}
	var api smithy.APIError
	kind := Unavailable
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			kind = Permission
		case "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch", "InvalidSignatureException", "MissingAuthenticationToken":
			kind = Authentication
		case "ResourceNotFoundException", "DBInstanceNotFound", "DBInstanceNotFoundFault", "DBClusterNotFoundFault", "DBClusterNotFound":
			kind = NotFound
		}
	}
	if kind == Unavailable {
		var response *smithyhttp.ResponseError
		if errors.As(err, &response) {
			switch response.HTTPStatusCode() {
			case http.StatusUnauthorized:
				kind = Authentication
			case http.StatusForbidden:
				kind = Permission
			case http.StatusNotFound:
				kind = NotFound
			}
		}
		var malformed *smithy.DeserializationError
		if kind == Unavailable && errors.As(err, &malformed) && (response == nil || response.HTTPStatusCode() < 500 && response.HTTPStatusCode() != 429) {
			kind = Metadata
		}
	}
	return discoveryError(kind, err)
}
