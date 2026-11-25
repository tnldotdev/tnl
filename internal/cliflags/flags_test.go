package cliflags

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

func TestPositionalsFollowDeclaredOrder(t *testing.T) {
	cmd := &cobra.Command{Use: "sample"}
	var options struct {
		Mode string `arg:"" enum:"read,write" help:"Choose a mode."`
		File string `arg:"" optional:"" type:"path" help:"Input file."`
	}
	Bind(cmd, &options, false)
	got := Positionals(cmd)
	if len(got) != 2 || got[0].Name != "mode" || got[0].Type != "string" || got[0].Optional ||
		got[0].Usage != "Choose a mode." || !slices.Equal(got[0].Choices, []string{"read", "write"}) ||
		got[1].Name != "file" || got[1].Type != "path" || !got[1].Optional || got[1].Repeatable {
		t.Fatalf("unexpected positional declarations: %+v", got)
	}
}

func TestPositionalsIncludeCustomUsage(t *testing.T) {
	cmd := &cobra.Command{
		Use:         "wait [service...]",
		Annotations: map[string]string{"cliflags:arg:service...": "One or more services."},
	}
	got := Positionals(cmd)
	if len(got) != 1 || got[0].Name != "service" || got[0].Type != "string" ||
		!got[0].Optional || !got[0].Repeatable || got[0].Usage != "One or more services." {
		t.Fatalf("unexpected positional declarations: %+v", got)
	}
}
