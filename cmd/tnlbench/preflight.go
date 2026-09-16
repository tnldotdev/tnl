package main

import (
	"context"
	"fmt"
	"io"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

type preflightCommand struct {
	FlyOrg       string `name:"fly-org" env:"BENCH_FLY_ORG" required:"" help:"Fly organization slug."`
	FlyBinary    string `name:"fly-binary" env:"BENCH_FLY_BINARY" default:"flyctl" help:"Fly CLI executable."`
	ParentDomain string `name:"parent-domain" env:"BENCH_PARENT_DOMAIN" required:"" help:"Existing public Route 53 parent domain."`
	ParentZoneID string `name:"parent-zone-id" env:"BENCH_PARENT_ZONE_ID" required:"" help:"Bare Route 53 hosted-zone ID for the parent domain."`
	ACMEEmail    string `name:"acme-email" env:"BENCH_ACME_EMAIL" required:"" help:"ACME account contact email."`
}

func (c preflightCommand) Validate() error {
	return validateBenchmarkInfrastructure(c.ParentDomain, c.ParentZoneID, c.ACMEEmail)
}

func (c preflightCommand) run(ctx context.Context, stdout io.Writer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	fly := flyPlatform{binary: c.FlyBinary, org: c.FlyOrg, executor: osCommandExecutor{}}
	if err := fly.preflight(ctx); err != nil {
		return err
	}
	if err := fly.validateOrg(ctx); err != nil {
		return err
	}
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"))
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	if _, err := awsConfig.Credentials.Retrieve(ctx); err != nil {
		return fmt.Errorf("retrieve AWS credentials: %w", err)
	}
	dns := benchmarkDNS{client: route53.NewFromConfig(awsConfig)}
	if err := dns.validateParentZone(ctx, c.ParentZoneID, c.ParentDomain); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Preflight: ready (no resources created)")
	return nil
}
