package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/aws/smithy-go"
	"github.com/tnldotdev/tnl/internal/failure"
	awsbootstrap "github.com/tnldotdev/tnl/internal/publisher/deployment/aws"
)

func TestBootstrapCommandIsPositionalAndPrepareOnly(t *testing.T) {
	for _, args := range [][]string{{"bootstrap"}, {"bootstrap", "aws", "production"}, {"bootstrap", "production", "--group", "production"}, {"bootstrap", "production", "--deploy"}, {"bootstrap", "production", "--prepare"}, {"bootstrap", "production", "--no-deploy"}} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err == nil {
			t.Fatal("unsupported bootstrap syntax accepted", args)
		}
	}
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"bootstrap", "production", "--profile", "company", "--region", "us-east-1", "--deployment-file", "deploy/aws.json", "--deployment", "east", "--output=json"})
	if err != nil || parsed.Command() != "bootstrap <publisher>" || flags.Bootstrap.Publisher != "production" || !projectSensitiveCommand(parsed.Command()) {
		t.Fatal("bootstrap positional contract", err)
	}
}

func TestBootstrapInvalidSourceDoesNotLoadAWS(t *testing.T) {
	loaded := false
	load := func(context.Context, string, string) (awsbootstrap.Secrets, awsbootstrap.Caller, error) {
		loaded = true
		return nil, nil, errors.New("unexpected provider access")
	}
	err := runBootstrapUsing(t.Context(), bootstrapCommand{Publisher: "production"}, projectConfiguration{}, io.Discard, io.Discard, load)
	if err == nil || loaded {
		t.Fatal("invalid project reached AWS")
	}
}

func TestBootstrapProviderDiagnosticDoesNotExposeCause(t *testing.T) {
	secret := "private-provider-response-body"
	err := failure.Wrap("store publisher identity", failure.AWSBootstrapDenied, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: secret})
	var output bytes.Buffer
	writeCommandError(&output, err)
	if bytes.Contains(output.Bytes(), []byte(secret)) || !bytes.Contains(output.Bytes(), []byte("AWS denied")) {
		t.Fatal("unsafe provider diagnostic", output.String())
	}
}
