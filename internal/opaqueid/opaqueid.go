// Package opaqueid creates and validates prefixed, cryptographically random identifiers.
package opaqueid

import (
	"strings"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

const (
	alphabet      = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	encodedLength = 22
)

const (
	ACMEAccountPrefix                = "aa_"
	ACMEAuthorizationPrefix          = "aau_"
	ACMEPresentationPrefix           = "ap_"
	ClaimPrefix                      = "cl_"
	ControlSessionPrefix             = "cs_"
	DNSAuthorityPrefix               = "da_"
	DNSWorkerPrefix                  = "dw_"
	DomainPrefix                     = "dom_"
	DrainPrefix                      = "dr_"
	GuestPrefix                      = "gst_"
	IdempotencyPrefix                = "ik_"
	IdentityPrefix                   = "ident_"
	IngressRunPrefix                 = "ir_"
	InstallationPrefix               = "inst_"
	InvitationPrefix                 = "ivt_"
	InvocationPrefix                 = "ivk_"
	IssuancePrefix                   = "iss_"
	MembershipPrefix                 = "mem_"
	PublicURLPrefix                  = "url_"
	PublishRunPrefix                 = "pr_"
	PublicURLCertificateWorkerPrefix = "ucw_"
	PublicURLUsageWorkerPrefix       = "uuw_"
	PublisherConnectionPrefix        = "pc_"
	RelayACMEPresentationPrefix      = "rap_"
	RelayCertificateOrderPrefix      = "rco_"
	RelayCertificateWorkerPrefix     = "rcw_"
	RelayRunPrefix                   = "rr_"
	RequestPrefix                    = "req_"
	SlugReservationPrefix            = "sr_"
	TeamPrefix                       = "tm_"
	TunnelPrefix                     = "tun_"
	UsageReportPrefix                = "ur_"
	VisitorConnectionPrefix          = "vc_"
)

// New returns a type prefix followed by 22 uniformly sampled alphanumeric characters.
func New(prefix string) (string, error) {
	id, err := gonanoid.Generate(alphabet, encodedLength)
	if err != nil {
		return "", err
	}
	return prefix + id, nil
}

// Valid reports whether value is prefix followed by exactly 22 alphanumeric characters.
func Valid(value, prefix string) bool {
	if len(value) != len(prefix)+encodedLength || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
			return false
		}
	}
	return true
}
