package tnldruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// route53AWSConfig exchanges a fresh Fly Machine identity token for temporary
// AWS credentials whenever STS credentials expire. Non-Fly deployments keep
// using the normal AWS SDK credential chain.
func route53AWSConfig(ctx context.Context, region string) (aws.Config, error) {
	roleARN := os.Getenv("AWS_ROLE_ARN")
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if roleARN != "" && os.Getenv("FLY_APP_NAME") != "" {
		// Avoid resolving old static credentials while constructing the STS client.
		options = append(options, awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}))
	}
	config, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return aws.Config{}, err
	}
	if roleARN != "" && os.Getenv("FLY_APP_NAME") != "" {
		provider := stscreds.NewWebIdentityRoleProvider(sts.NewFromConfig(config), roleARN, flyIdentityTokenRetriever())
		config.Credentials = aws.NewCredentialsCache(provider)
	}
	return config, nil
}

type flyTokenRetriever struct{ client *http.Client }

func flyIdentityTokenRetriever() flyTokenRetriever {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/.fly/api")
	}}
	return flyTokenRetriever{client: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
}

func (r flyTokenRetriever) GetIdentityToken() ([]byte, error) {
	request, err := http.NewRequest(http.MethodPost, "http://fly/v1/tokens/oidc", strings.NewReader(`{"aud":"sts.amazonaws.com"}`))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request Fly OIDC token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request Fly OIDC token: status %d", response.StatusCode)
	}
	token, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	if err != nil {
		return nil, fmt.Errorf("read Fly OIDC token: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) == 0 || len(token) > 16*1024 {
		return nil, errors.New("fly OIDC token is empty or too large")
	}
	return token, nil
}
