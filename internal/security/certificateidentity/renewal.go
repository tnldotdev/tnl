package certificateidentity

import "time"

// RenewAt schedules renewal after two thirds of the certificate's validity.
// publication owners handle retries and stop serving at the actual expiry.
func RenewAt(notBefore, notAfter time.Time) time.Time {
	return notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC()
}
