package webhookprovider

import "slices"

// names is the bounded provider enum shared by the control API and client config.
var names = []string{
	"amazon-sns", "auth0", "clerk", "custom", "discord", "github", "gitlab", "incident-io",
	"lemon-squeezy", "linear", "loops", "paddle", "postmark", "resend", "sendgrid", "shopify",
	"slack", "stripe", "supabase", "telegram", "twilio", "vercel", "workos",
}

func Names() []string { return slices.Clone(names) }

func Valid(name string) bool { return slices.Contains(names, name) }
