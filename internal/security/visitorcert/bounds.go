// package visitorcert owns shared client-certificate rules.
package visitorcert

import (
	"errors"
	"time"
)

const MaxLifetime = 7 * 24 * time.Hour
const MaxWorkloadLifetime = 6 * time.Hour

// IssuerCommonName is the stable issuer name in tnl client certificates.
const IssuerCommonName = "tnl service client issuer"

var ErrInvalidCertificate = errors.New("invalid service client certificate")

// WorkloadDeadline bounds key identity independently of renewable permission.
// a later lease or provider proof cannot change this certificate's fixed expiry.
func WorkloadDeadline(now time.Time, absolute *time.Time) time.Time {
	until := now.Add(MaxWorkloadLifetime)
	if absolute != nil && absolute.Before(until) {
		until = *absolute
	}
	return until
}
