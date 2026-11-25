package main

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tnldotdev/tnl/internal/client/background"
)

// registerBackgroundFlag binds an alternate spelling to the same bool value.
// pflag still handles ordering, explicit false, help and completion.
func registerBackgroundFlag(cmd *cobra.Command) {
	short := cmd.Flags().Lookup("bg")
	if short == nil || short.NoOptDefVal != "true" {
		panic("background alias requires a boolean --bg flag")
	}
	cmd.Flags().AddFlag(&pflag.Flag{
		Name: "background", Usage: "Same as --bg.", Value: short.Value,
		DefValue: short.DefValue, NoOptDefVal: short.NoOptDefVal,
	})
}

// backgroundInvocation carries parsed options privately, not a second command
// line. changed flags distinguish explicit overrides from environment values.
type backgroundInvocation struct {
	Cwd         string
	ConfigPath  string
	NoConfig    bool
	NoProgress  bool
	NoTelemetry bool
	Changed     []string
	Publish     *publishCommand
	Connect     *connectStartCommand
	Publisher   *publisherServeCommand
}

func parsedBackgroundInvocation(f *cli, cmd *cobra.Command, kind background.Kind) backgroundInvocation {
	inv := backgroundInvocation{Cwd: f.Cwd, ConfigPath: f.ConfigPath, NoConfig: f.NoConfig, NoProgress: f.NoProgress, NoTelemetry: f.NoTelemetry}
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		inv.Changed = append(inv.Changed, flag.Name)
	})
	switch kind {
	case background.KindPublish:
		opts := f.Publish
		opts.Background, opts.Output = false, publishOutputHuman
		inv.Publish = &opts
	case background.KindConnect:
		opts := f.Connect.Start
		opts.Background, opts.Output = false, statusOutputHuman
		inv.Connect = &opts
	case background.KindPublisher:
		opts := f.Publisher.Serve
		opts.Background, opts.Output = false, statusOutputHuman
		inv.Publisher = &opts
	}
	return inv
}

func (inv backgroundInvocation) restore(f *cli, kind background.Kind, root string) ([]string, error) {
	f.Cwd, f.ConfigPath, f.NoConfig = inv.Cwd, inv.ConfigPath, inv.NoConfig
	f.NoProgress, f.NoTelemetry = inv.NoProgress, inv.NoTelemetry
	switch kind {
	case background.KindPublish:
		if inv.Publish != nil && inv.Connect == nil && inv.Publisher == nil &&
			!inv.Publish.Background && !inv.Publish.Foreground && !inv.Publish.Install && inv.Publish.EnrollmentKey != "-" {
			f.Publish = *inv.Publish
			f.Publish.StateDir, f.Publish.Output = root, publishOutputHuman
			return []string{"publish"}, nil
		}
	case background.KindConnect:
		if inv.Connect != nil && inv.Publish == nil && inv.Publisher == nil &&
			!inv.Connect.Background && !inv.Connect.Foreground && !inv.Connect.Install && !inv.Connect.Stdio && inv.Connect.Client == "" {
			f.Connect.Start = *inv.Connect
			f.Connect.Start.StateDir, f.Connect.Start.Output = root, statusOutputHuman
			return []string{"connect", "start"}, nil
		}
	case background.KindPublisher:
		if inv.Publisher != nil && inv.Publish == nil && inv.Connect == nil &&
			!inv.Publisher.Background && !inv.Publisher.Foreground && !inv.Publisher.Install && inv.Publisher.EnrollmentKey != "-" {
			f.Publisher.Serve = *inv.Publisher
			f.Publisher.Serve.StateDir, f.Publisher.Serve.Output = root, statusOutputHuman
			return []string{"publisher", "serve"}, nil
		}
	}
	return nil, errors.New("invalid background operation")
}
