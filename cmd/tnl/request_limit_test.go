package main

import (
	"os"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestPublisherRequestLimitPrecedence(t *testing.T) {
	for _, command := range []string{"publish", "dev"} {
		for _, test := range []struct {
			name          string
			root, service *int
			env, flag     string
			want          int
		}{
			{name: "default", want: 500},
			{name: "root", root: new(600), want: 600},
			{name: "service", root: new(600), service: new(700), want: 700},
			{name: "environment", root: new(600), service: new(700), env: "800", want: 800},
			{name: "flag", root: new(600), service: new(700), env: "800", flag: "900", want: 900},
			{name: "zero flag", root: new(600), flag: "0", want: -1},
			{name: "negative flag", flag: "-1", want: -1},
			{name: "zero environment", root: new(600), env: "0", want: -1},
		} {
			t.Run(command+"/"+test.name, func(t *testing.T) {
				t.Setenv("TNL_REQUEST_LIMIT", test.env)
				if test.env == "" {
					if err := os.Unsetenv("TNL_REQUEST_LIMIT"); err != nil {
						t.Fatal(err)
					}
				}
				var flags cli
				parser, err := kong.New(&flags)
				if err != nil {
					t.Fatal(err)
				}
				args := []string{command, "web"}
				if test.flag != "" {
					args = append(args, "--request-limit="+test.flag)
				}
				if _, err := parser.Parse(args); err != nil {
					t.Fatal(err)
				}
				target := config.Target("3000")
				project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
					Tunnel:   &config.Tunnel{RequestLimit: test.root},
					Services: config.Services{"web": {Tunnel: &config.Tunnel{RequestLimit: test.service}, Publish: &config.Publish{Target: &target}}},
				}}}
				var tunnel tunnelFlags
				if command == "publish" {
					err = project.applyPublish(&flags.Publish)
					tunnel = flags.Publish.tunnelFlags
				} else {
					err = project.applyDev(&flags.Dev)
					tunnel = flags.Dev.tunnelFlags
				}
				if test.want == -1 {
					if err == nil {
						t.Fatal("nonpositive request limit accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if got := tunnel.requestLimit(); got != test.want {
					t.Fatalf("request limit = %d, want %d", got, test.want)
				}
			})
		}
	}
}
