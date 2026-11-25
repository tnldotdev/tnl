package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/buildinfo"
)

func (a *commandApp) newCheckCommand() *cobra.Command {
	f := a.flags
	cCheck := &cobra.Command{Use: "check", Short: "Validate the project configuration and print its path.", GroupID: "project"}
	a.leaf(cCheck, &f.Check, func(call commandCall) error {
		project, err := loadProjectConfigurationWithSalt(call.ctx, *f, [32]byte{})
		if err != nil {
			return err
		}
		return runCheck(project, a.out)
	})
	return cCheck
}

func (a *commandApp) newWebhookCommand() *cobra.Command {
	f := a.flags
	cWebhook := &cobra.Command{
		Use: "webhook", Short: "Choose which worktree receives a webhook.", GroupID: "project",
		Long: "For a webhook configured with selected delivery, send events to the running service in this worktree. The provider keeps using the same webhook URL.",
	}
	cWebhookUse := &cobra.Command{Use: "use", Short: "Send this webhook to the ready service in this worktree."}
	a.leaf(cWebhookUse, &f.Webhook.Use, func(call commandCall) error {
		return runWebhookChoice(call.ctx, f.Webhook.Use.webhookChoiceCommand, call.project, true, f.Webhook.Use.Force, a.out)
	})
	cWebhook.AddCommand(cWebhookUse)
	cWebhookRelease := &cobra.Command{Use: "release", Short: "Stop sending this webhook to this worktree."}
	a.leaf(cWebhookRelease, &f.Webhook.Release, func(call commandCall) error {
		return runWebhookChoice(call.ctx, f.Webhook.Release, call.project, false, false, a.out)
	})
	cWebhook.AddCommand(cWebhookRelease)
	return cWebhook
}

func (a *commandApp) newAliasCommand() *cobra.Command {
	f := a.flags
	cAlias := &cobra.Command{Use: "alias", Short: "Choose which worktree serves a project alias.", GroupID: "project"}
	cAliasUse := &cobra.Command{Use: "use", Short: "Use this worktree for an alias."}
	a.leaf(cAliasUse, &f.Alias.Use, func(call commandCall) error {
		return runAliasChoice(call.ctx, f.Alias.Use.aliasChoiceCommand, call.project, true, f.Alias.Use.Force, a.out, a.errOut)
	})
	cAlias.AddCommand(cAliasUse)
	cAliasRelease := &cobra.Command{Use: "release", Short: "Return the alias to the primary checkout."}
	a.leaf(cAliasRelease, &f.Alias.Release, func(call commandCall) error {
		return runAliasChoice(call.ctx, f.Alias.Release, call.project, false, false, a.out, a.errOut)
	})
	cAlias.AddCommand(cAliasRelease)
	return cAlias
}

func (a *commandApp) newVersionCommand() *cobra.Command {
	f := a.flags
	cVersion := &cobra.Command{Use: "version", Short: "Print the installed tnl version.", GroupID: "tools"}
	a.leaf(cVersion, &f.Version, func(call commandCall) error {
		_, err := fmt.Fprintln(a.out, buildinfo.Line("tnl"))
		return err
	})
	return cVersion
}
