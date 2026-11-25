package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/naming"
)

// completionRole names the source of suggestions, not the values a command
// accepts. structured help can describe the role without reading local facts.
type completionRole string

const (
	completeService    completionRole = "project-service"
	completeDeployment completionRole = "deployment"
	completeClient     completionRole = "connect-client"
	completeCommand    completionRole = "command-path"
)

type serviceSelection uint8

const (
	selectSingleService serviceSelection = iota
	selectMultipleServices
	selectDeploymentService
)

type completionInput struct {
	role     completionRole
	services serviceSelection
}

type completionSpec struct {
	argument completionInput
	flags    map[string]completionInput
}

// completionRoles describes the first positional input and named flags.
func completionRoles(cmd *cobra.Command) (completionRole, map[string]completionRole) {
	spec := projectCompletionSpec(cmd)
	flags := make(map[string]completionRole, len(spec.flags))
	for name, input := range spec.flags {
		flags[name] = input.role
	}
	return spec.argument.role, flags
}

func projectCompletionSpec(cmd *cobra.Command) completionSpec {
	if !publicCommandPath(cmd) {
		return completionSpec{}
	}
	spec := completionSpec{flags: map[string]completionInput{}}
	addFlag := func(name string, input completionInput) {
		if flag := cmd.Flags().Lookup(name); flag != nil && !flag.Hidden {
			spec.flags[name] = input
		}
	}
	addFlag("deployment", completionInput{role: completeDeployment})
	service := completionInput{role: completeService}
	switch selectedPath(cmd) {
	case "wait":
		service.services = selectMultipleServices
		spec.argument = service
		addFlag("service", service)
	case "status", "watch", "inspect list", "share create", "audit list":
		spec.argument = service
		addFlag("service", service)
	case "publish":
		spec.argument = service
	case "connect start":
		spec.argument = service
		addFlag("client", completionInput{role: completeClient})
	case "publisher setup", "publisher provision":
		addFlag("service", completionInput{role: completeService, services: selectDeploymentService})
	case "help":
		spec.argument = completionInput{role: completeCommand}
	}
	return spec
}

func completionFacts(cmd *cobra.Command) meta.Completion {
	if off, _ := cmd.Flags().GetBool("no-config"); off {
		return meta.Completion{}
	}
	path := os.Getenv("TNL_CONFIG")
	if f := cmd.Flags().Lookup("config"); f != nil && f.Changed {
		path = f.Value.String()
	}
	var dir string
	if flag := cmd.Flags().Lookup("cwd"); flag != nil && flag.Changed {
		var err error
		dir, err = resolveCheckout(flag.Value.String())
		if err != nil || dir == "" {
			return meta.Completion{}
		}
	}
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return meta.Completion{}
		}
	}
	if path != "" {
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		return meta.ReadCompletion(filepath.Dir(path))
	}
	for {
		for _, name := range clientproject.ConfigNames() {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return meta.ReadCompletion(dir)
			}
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil || dir == filepath.Dir(dir) {
			return meta.ReadCompletion(dir)
		}
		dir = filepath.Dir(dir)
	}
}

func completeNames(values []string, prefix string) ([]cobra.Completion, cobra.ShellCompDirective) {
	slices.Sort(values)
	values = slices.DeleteFunc(values, func(s string) bool { return !strings.HasPrefix(s, prefix) })
	return slices.Compact(values), cobra.ShellCompDirectiveNoFileComp
}

func completeProjectServices(cmd *cobra.Command, prefix string, used []string, positional bool) ([]cobra.Completion, cobra.ShellCompDirective) {
	var completions []cobra.Completion
	for name, protocol := range completionFacts(cmd).Services {
		if !strings.HasPrefix(name, prefix) || slices.Contains(used, name) {
			continue
		}
		if positional && slices.ContainsFunc(cmd.Commands(), func(sub *cobra.Command) bool { return sub.Name() == name || sub.HasAlias(name) }) {
			continue
		}
		// the shell inserts the name; the protocol is display text only.
		completions = append(completions, cobra.CompletionWithDesc(name, protocol))
	}
	slices.Sort(completions)
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeConnectClients(cmd *cobra.Command, args []string, prefix string) ([]cobra.Completion, cobra.ShellCompDirective) {
	if len(args) != 1 {
		return cobra.NoFileCompletions(cmd, args, prefix)
	}
	selector, err := naming.ParseServiceSelector(args[0])
	if err != nil || selector.Resource {
		return cobra.NoFileCompletions(cmd, args, prefix)
	}
	protocol := selector.Protocol
	if selector.Kind == naming.SelectorName {
		protocol = completionFacts(cmd).Services[selector.Name]
	}
	return completeNames(connector.ClientNames(protocol), prefix)
}

func (input completionInput) callback(positional bool, waitServices *[]string) cobra.CompletionFunc {
	switch input.role {
	case completeService:
		return func(cmd *cobra.Command, args []string, prefix string) ([]cobra.Completion, cobra.ShellCompDirective) {
			var used []string
			switch input.services {
			case selectSingleService:
				if len(args) != 0 || cmd.Flags().Changed("service") {
					return cobra.NoFileCompletions(cmd, args, prefix)
				}
			case selectMultipleServices:
				used = slices.Concat(args, *waitServices)
			case selectDeploymentService:
				deployment, _ := cmd.Flags().GetString("deployment")
				key, _ := cmd.Flags().GetString("project-key")
				if deployment == "" || key != "" {
					return cobra.NoFileCompletions(cmd, args, prefix)
				}
			}
			return completeProjectServices(cmd, prefix, used, positional)
		}
	case completeDeployment:
		return func(cmd *cobra.Command, _ []string, prefix string) ([]cobra.Completion, cobra.ShellCompDirective) {
			return completeNames(completionFacts(cmd).Deployments, prefix)
		}
	case completeClient:
		return completeConnectClients
	case completeCommand:
		return completeHelpTopic
	}
	return nil
}

func registerProjectCompletions(root *cobra.Command, waitServices *[]string) {
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if cmd.Name() != cobra.ShellCompRequestCmd || len(args) == 0 {
			return
		}
		// cobra may suggest subcommands or flags before it calls a custom
		// callback. fence hidden paths and -- before reaching that logic.
		// the last token is still being typed; it is not a delimiter yet.
		target, rest, err := root.Find(args[:len(args)-1])
		if err != nil || (publicCommandPath(target) && !completionPastDash(target, rest)) {
			return
		}
		cmd.Run = func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), ":%d\n", cobra.ShellCompDirectiveNoFileComp)
		}
	}
	var visit func(*cobra.Command)
	visit = func(cmd *cobra.Command) {
		spec := projectCompletionSpec(cmd)
		if complete := spec.argument.callback(true, waitServices); complete != nil {
			cmd.ValidArgsFunction = complete
		}
		for name, input := range spec.flags {
			if _, ok := cmd.GetFlagCompletionFunc(name); !ok {
				if err := cmd.RegisterFlagCompletionFunc(name, input.callback(false, waitServices)); err != nil {
					panic(err)
				}
			}
		}
		for _, sub := range cmd.Commands() {
			visit(sub)
		}
	}
	visit(root)
}

// completionPastDash inspects the raw arguments. cobra parses flags twice
// during completion and inserts a synthetic -- on its first pass.
func completionPastDash(cmd *cobra.Command, args []string) bool {
	flags := cmd.Flags()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return true
		}
		if name, ok := strings.CutPrefix(arg, "--"); ok && !strings.Contains(name, "=") {
			if flag := flags.Lookup(name); flag != nil && flag.NoOptDefVal == "" {
				i++ // consume the flag value, even if it is "--"
			}
		}
	}
	return false
}
