package control_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/applicationhttp"
)

func TestIntegrationApplicationHTTPWebCryptoAgainstControl(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "application_sdk_http")
	applicationhttp.Qualify(t, databaseURL, func(input applicationhttp.Inputs, mode string) {
		t.Helper()
		command := exec.CommandContext(t.Context(), "node", "packages/ts/test/fixtures/application-http-control.ts", input.CredentialFile, input.ResourceID, input.Origin, mode)
		command.Dir = input.Directory
		command.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+input.CAFile)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("SDK authority check %s: %v\n%s", mode, err, output)
		}
	})
}
