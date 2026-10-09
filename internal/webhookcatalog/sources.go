package webhookcatalog

type definition struct {
	url, field string
	static     []string
}

// static addresses are from the providers' linked webhook/firewall documentation.
var sources = map[string]definition{
	"github": {url: "https://api.github.com/meta", field: "hooks"},
	"stripe": {url: "https://stripe.com/files/ips/ips_webhooks.json", field: "WEBHOOKS"},
	"linear": {url: "https://linear.app/.well-known/appspecific/app.linear.ips.json", field: "ips"},
	// clerk explicitly recommends the Svix sender feed for its webhooks.
	"clerk": {url: "https://docs.svix.com/webhook-ips.json"},
	"auth0": {url: "https://cdn.auth0.com/ip-ranges.json"},
	// https://docs.gitlab.com/user/gitlab_com/#ip-range (gitlab.com only)
	"gitlab": {static: []string{"34.74.90.64/28", "34.74.226.0/24"}},
	// https://developer.paddle.com/webhooks/about/respond-to-webhooks (sandbox and live)
	"paddle": {static: []string{
		"34.194.127.46", "54.234.237.108", "3.208.120.145", "44.226.236.210",
		"44.241.183.62", "100.20.172.113", "34.232.58.13", "34.195.105.136",
		"34.237.3.244", "35.155.119.135", "52.11.166.252", "34.212.5.7",
	}},
	// https://postmarkapp.com/support/article/800-ips-for-firewalls#webhooks
	"postmark": {static: []string{"3.134.147.250", "50.31.156.6", "50.31.156.77", "18.217.206.57"}},
	// https://resend.com/docs/webhooks/create-webhook#what-ips-do-webhooks-post-from
	"resend": {static: []string{"44.228.126.217", "50.112.21.217", "52.24.126.164", "54.148.139.208", "2600:1f24:64:8000::/52"}},
	// https://core.telegram.org/bots/webhooks (setWebhook traffic)
	"telegram": {static: []string{"149.154.160.0/20", "91.108.4.0/22"}},
	// https://workos.com/docs/events/data-syncing/webhooks
	"workos": {static: []string{
		"3.217.146.166", "23.21.184.92", "34.204.154.149", "35.82.80.13",
		"44.213.245.178", "44.215.236.82", "44.253.112.118", "50.16.203.9",
		"52.1.251.34", "52.21.49.187", "54.68.143.104", "100.22.25.25",
		"100.22.157.11", "100.22.247.20", "174.129.36.47",
	}},
}
