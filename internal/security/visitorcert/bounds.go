// package visitorcert owns the shared client-certificate bounds and error.
package visitorcert

import (
	"errors"
	"time"
)

const MaxLifetime = 7 * 24 * time.Hour
const MaxWorkloadLifetime = 6 * time.Hour

var ErrInvalidCertificate = errors.New("invalid service client certificate")
