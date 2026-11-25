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

func completionFacts(cmd *cobra.Command) meta.Completion {
	if off, _ := cmd.Flags().GetBool("no-config"); off {
		return meta.Completion{}
	}
	path := os.Getenv("TNL_CONFIG")
	if f := cmd.Flags().Lookup("config"); f != nil && f.Changed {
		path = f.Value.String()
	}
	if path != "" {
		return meta.ReadCompletion(filepath.Dir(path))
	}
	dir, err := os.Getwd()
	if err != nil {
		return meta.Completion{}
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

func completeNames(values []string, prefix string) ([]string, cobra.ShellCompDirective) {
	slices.Sort(values)
	return slices.DeleteFunc(values, func(s string) bool { return !strings.HasPrefix(s, prefix) }), cobra.ShellCompDirectiveNoFileComp
}

func completeProjectServices(cmd *cobra.Command, prefix string, used []string, positional bool) ([]string, cobra.ShellCompDirective) {
	var completions []string
	for name, protocol := range completionFacts(cmd).Services {
		if !strings.HasPrefix(name, prefix) || slices.Contains(used, name) {
			continue
		}
		if positional && slices.ContainsFunc(cmd.Commands(), func(sub *cobra.Command) bool { return sub.Name() == name || sub.HasAlias(name) }) {
			continue
		}
		completions = append(completions, cobra.CompletionWithDesc(name, protocol))
	}
	slices.Sort(completions)
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeConnectClients(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
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

func positionalServiceCompletion(path string) bool {
	switch path {
	case "status", "wait", "watch", "share create", "inspect list", "audit list", "publish", "connect start":
		return true
	default:
		return false
	}
}

func registerProjectCompletions(root *cobra.Command, waitServices *[]string) {
	// cobra parses completion flags twice, inserting a synthetic -- on its
	// first pass. inspect the raw completion request rather than ArgsLenAtDash.
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if cmd.Name() != cobra.ShellCompRequestCmd || len(args) < 2 {
			return
		}
		if dash := slices.Index(args[:len(args)-1], "--"); dash >= 0 {
			target, _, err := root.Find(args[:dash])
			if err == nil && positionalServiceCompletion(selectedPath(target)) {
				cmd.Run = func(cmd *cobra.Command, _ []string) {
					fmt.Fprintf(cmd.OutOrStdout(), ":%d\n", cobra.ShellCompDirectiveNoFileComp)
				}
			}
		}
	}
	deployments := func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		return completeNames(completionFacts(cmd).Deployments, prefix)
	}
	deploymentServices := func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		deployment, _ := cmd.Flags().GetString("deployment")
		key, _ := cmd.Flags().GetString("project-key")
		if deployment == "" || key != "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return completeProjectServices(cmd, prefix, nil, false)
	}
	register := func(cmd *cobra.Command, name string, complete cobra.CompletionFunc) {
		if _, ok := cmd.GetFlagCompletionFunc(name); ok {
			return
		}
		if err := cmd.RegisterFlagCompletionFunc(name, complete); err != nil {
			panic(err)
		}
	}
	var visit func(*cobra.Command)
	visit = func(cmd *cobra.Command) {
		if cmd.Flags().Lookup("deployment") != nil {
			register(cmd, "deployment", deployments)
		}
		path := selectedPath(cmd)
		switch path {
		case "wait":
			register(cmd, "service", func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
				return completeProjectServices(cmd, prefix, slices.Concat(args, *waitServices), false)
			})
		case "status", "watch", "inspect list", "share create", "audit list":
			register(cmd, "service", func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
				if len(args) != 0 || cmd.Flags().Changed("service") {
					return cobra.NoFileCompletions(cmd, args, prefix)
				}
				return completeProjectServices(cmd, prefix, nil, false)
			})
		case "publisher setup", "publisher provision":
			register(cmd, "service", deploymentServices)
		case "connect start":
			register(cmd, "client", completeConnectClients)
		}
		if positionalServiceCompletion(path) {
			cmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
				if path == "wait" {
					return completeProjectServices(cmd, prefix, slices.Concat(args, *waitServices), true)
				}
				if len(args) != 0 || cmd.Flags().Changed("service") {
					return cobra.NoFileCompletions(cmd, args, prefix)
				}
				return completeProjectServices(cmd, prefix, nil, true)
			}
		}
		for _, sub := range cmd.Commands() {
			visit(sub)
		}
	}
	visit(root)
}
