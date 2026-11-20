package main

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
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

func registerProjectCompletions(root *cobra.Command) {
	services := func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		return completeNames(slices.Collect(maps.Keys(completionFacts(cmd).Services)), prefix)
	}
	deployments := func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		return completeNames(completionFacts(cmd).Deployments, prefix)
	}
	deploymentServices := func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		deployment, _ := cmd.Flags().GetString("deployment")
		key, _ := cmd.Flags().GetString("project-key")
		if deployment == "" || key != "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return services(cmd, args, prefix)
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
		// a flag named --service can select a project name or an exact saved ID.
		switch selectedPath(cmd) {
		case "wait", "inspect list", "share create", "audit list":
			register(cmd, "service", services)
		case "publisher setup", "publisher provision":
			register(cmd, "service", deploymentServices)
		}
		switch cmd.CommandPath() {
		case "tnl connect", "tnl connect start":
			cmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
				if len(args) != 0 {
					return nil, cobra.ShellCompDirectiveNoFileComp
				}
				return services(cmd, args, prefix)
			}
		}
		for _, sub := range cmd.Commands() {
			visit(sub)
		}
	}
	visit(root)
}
