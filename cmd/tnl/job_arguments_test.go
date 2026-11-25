package main

import (
	"encoding/json"
	"io"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/background"
)

func TestBackgroundFlagSpellingsShareOneValue(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"--bg"}, true},
		{[]string{"--background"}, true},
		{[]string{"--bg", "--background=false"}, false},
		{[]string{"--background=false", "--bg"}, true},
	} {
		for _, invocation := range [][]string{{"publish", "3000"}, {"connect", "orders"}, {"publisher", "serve"}} {
			var flags cli
			parse := commandForTest(&flags, io.Discard)
			args := append(slices.Clone(invocation), tc.args...)
			_, err := parse(args)
			chosen := flags.Publish.Background || flags.Connect.Start.Background || flags.Publisher.Serve.Background
			if err != nil || chosen != tc.want {
				t.Fatalf("%v: %t, %v; want %t", args, chosen, err, tc.want)
			}
		}
	}
}

func TestBackgroundInvocationCarriesParsedValues(t *testing.T) {
	var flags cli
	t.Setenv("TNL_SERVER", "https://control.example")
	t.Setenv("TNL_STATE_DIR", "/private/client state")
	parse := commandForTest(&flags, io.Discard)
	cmd, err := parse([]string{"--cwd", "/checkout with spaces", "--no-config", "publish", "3000", "--background", "--ip", "10.0.0.0/8", "--ip=192.168.0.0/16", "--team", "team", "--target-tls=false", "--output=json"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(parsedBackgroundInvocation(&flags, cmd, background.KindPublish))
	if err != nil {
		t.Fatal(err)
	}
	var decoded backgroundInvocation
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	var restored cli
	path, err := decoded.restore(&restored, background.KindPublish, "/canonical/client state")
	publish := restored.Publish
	if err != nil || !slices.Equal(path, []string{"publish"}) || !restored.NoConfig || restored.Cwd != "/checkout with spaces" ||
		publish.Target != "3000" || publish.Background || publish.Output != publishOutputHuman ||
		publish.StateDir != "/canonical/client state" || publish.ServerURL != "https://control.example" || publish.Team != "team" ||
		!slices.Equal(publish.IP, []string{"10.0.0.0/8", "192.168.0.0/16"}) || publish.TargetTLS == nil || *publish.TargetTLS ||
		!slices.Contains(decoded.Changed, "target-tls") || slices.Contains(decoded.Changed, "server") {
		t.Fatalf("invalid restored operation: %+v, %v", publish, err)
	}
}
