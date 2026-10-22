package awsbootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCustomerDeploymentInputIsBoundedAndNetworkOptional(t *testing.T) {
	for _, input := range []struct {
		data  string
		valid bool
	}{
		{`{"schema_version":1,"deployments":[{"name":"prod","publisher":"production","account_id":"123456789012","region":"us-east-1"}]}`, true},
		{`{"schema_version":1,"deployments":[{"name":"prod","publisher":"production","account_id":"123456789012","region":"us-east-1","parameters":{"TaskCPU":"256"},"identity_secrets":{"replica-1":{"name":"customer/replica","kms_key_id":"alias/publishers"}}}]}`, true},
		{`{"schema_version":1,"schema_version":1,"deployments":[]}`, false},
		{`{"schema_version":1,"deployments":[{"name":"prod","publisher":"production","account_id":"123456789012","region":"us-east-1","vpc":"vpc-secret"}]}`, false},
		{strings.Repeat(" ", 256<<10) + `{}`, false},
	} {
		path := filepath.Join(t.TempDir(), "aws.json")
		if err := os.WriteFile(path, []byte(input.data), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadDeployment(path, "production", "")
		if (err == nil) != input.valid {
			t.Fatal("deployment validation differs", err)
		}
	}
}
