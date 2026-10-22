package aws

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"
	"github.com/tnldotdev/tnl/internal/failure"
)

// Secrets is deliberately limited to one secret's identity lifecycle. there is
// no deployment API, resource enumeration, deletion, or tag mutation capability.
type Secrets interface {
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}

type Caller interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Load is called only by bootstrap. SDK endpoint overrides are disabled; tests
// inject clients pointed at their local HTTPS fixture. retries are bounded by
// both the SDK attempt count and the command context, without background work.
func Load(ctx context.Context, profile, region string) (Secrets, Caller, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(region), config.WithRetryMaxAttempts(3)}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, nil, failure.Wrap("load AWS credentials", failure.AWSBootstrapAuthentication, err)
	}
	cfg.ClientLogMode = 0
	cfg.Logger = logging.Nop{}
	credentialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := cfg.Credentials.Retrieve(credentialCtx); err != nil {
		return nil, nil, failure.Wrap("load AWS credentials", failure.AWSBootstrapAuthentication, err)
	}
	return secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) { o.BaseEndpoint = nil }), sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = nil }), nil
}

func CheckAccount(ctx context.Context, caller Caller, expected string) error {
	response, err := caller.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return awsError("identify AWS account", err)
	}
	if response == nil || aws.ToString(response.Account) != expected {
		return failure.Wrap("identify AWS account", failure.AWSBootstrapScope, errScope)
	}
	return nil
}

func code(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}

func awsError(operation failure.Operation, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	reason := failure.AWSBootstrapUnavailable
	switch code(err) {
	case "AccessDenied", "AccessDeniedException", "DecryptionFailure", "DecryptionFailureException", "EncryptionFailure", "EncryptionFailureException":
		reason = failure.AWSBootstrapDenied
	case "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch", "InvalidSignatureException", "MissingAuthenticationToken":
		reason = failure.AWSBootstrapAuthentication
	case "Throttling", "ThrottlingException", "TooManyRequestsException", "LimitExceededException":
		reason = failure.AWSBootstrapThrottled
	case "ResourceExistsException":
		reason = failure.AWSBootstrapSecretConflict
		if operation == "store publisher identity version" || operation == "claim external identity container" {
			reason = failure.AWSBootstrapVersionConflict
		}
	case "InvalidRequestException", "InvalidParameterException":
		reason = failure.AWSBootstrapVersionConflict
	}
	return failure.Wrap(operation, reason, err)
}
