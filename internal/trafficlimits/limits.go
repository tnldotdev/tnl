// package trafficlimits defines normalized per-publish-run visitor budgets.
package trafficlimits

import (
	"errors"
	"fmt"
	"math/bits"
	"regexp"
	"strconv"
	"time"
)

const ByteRatePattern = `^[1-9][0-9]*(KiB|MiB|GiB)/s$`

var byteRatePattern = regexp.MustCompile(ByteRatePattern)

func Default() Limits {
	return Limits{Connections: 32, Rate: 20, RatePer: time.Second, Burst: 40,
		UploadBytes: 8 << 20, DownloadBytes: 16 << 20}
}

func Ceiling() Limits {
	return Limits{Connections: 128, Rate: 100, RatePer: time.Second, Burst: 200,
		UploadBytes: 64 << 20, DownloadBytes: 128 << 20}
}

func ParseByteRate(value string) (int64, error) {
	if !byteRatePattern.MatchString(value) {
		return 0, errors.New("byte rate must use a positive KiB/s, MiB/s, or GiB/s value")
	}
	unit := value[len(value)-5 : len(value)-2]
	amount, err := strconv.ParseInt(value[:len(value)-5], 10, 64)
	if err != nil {
		return 0, errors.New("byte rate is too large")
	}
	multiplier := int64(1 << 10)
	if unit == "MiB" {
		multiplier = 1 << 20
	} else if unit == "GiB" {
		multiplier = 1 << 30
	}
	if amount > (1<<40)/multiplier || amount*multiplier < 64<<10 {
		return 0, errors.New("byte rate must be between 64KiB/s and 1TiB/s")
	}
	return amount * multiplier, nil
}

// Limits are enforced independently on each ingress process. byte rates count
// encrypted connection bytes from and to the visitor, per second.
type Limits struct {
	Connections   int           `json:"connections"`
	Rate          int           `json:"rate"`
	RatePer       time.Duration `json:"rate_per_ns"`
	Burst         int           `json:"burst"`
	UploadBytes   int64         `json:"upload_bytes"`
	DownloadBytes int64         `json:"download_bytes"`
}

func (l Limits) Valid() bool {
	return l.Connections > 0 && l.Rate > 0 && l.Burst > 0 &&
		(l.RatePer == 0 || l.RatePer >= time.Millisecond && l.RatePer <= 24*time.Hour) &&
		l.UploadBytes >= 64<<10 && l.DownloadBytes >= 64<<10
}

// Selection is the subset explicitly chosen for one publish run. absent fields
// inherit the control service's defaults, not values from a saved public URL.
type Selection struct {
	Connections   *int    `json:"connections,omitempty"`
	Rate          *int    `json:"rate,omitempty"`
	RatePer       *string `json:"rate_per,omitempty"`
	Burst         *int    `json:"burst,omitempty"`
	UploadBytes   *int64  `json:"upload_bytes,omitempty"`
	DownloadBytes *int64  `json:"download_bytes,omitempty"`
}

func (s Selection) Validate() error {
	for _, value := range []*int{s.Connections, s.Rate, s.Burst} {
		if value != nil && *value <= 0 {
			return errors.New("traffic connection limits must be positive")
		}
	}
	for _, value := range []*int64{s.UploadBytes, s.DownloadBytes} {
		if value != nil && *value < 64<<10 {
			return errors.New("traffic bandwidth must be at least 64KiB/s")
		}
	}
	if s.RatePer != nil {
		period, err := time.ParseDuration(*s.RatePer)
		if err != nil || period < time.Millisecond || period > 24*time.Hour {
			return errors.New("traffic rate period must be between 1ms and 24h")
		}
	}
	return nil
}

func (s Selection) Resolve(defaults, ceiling Limits) (Limits, error) {
	if err := s.Validate(); err != nil {
		return Limits{}, err
	}
	if !defaults.Within(ceiling) {
		return Limits{}, errors.New("server traffic defaults exceed operator ceilings")
	}
	result := defaults
	if s.Connections != nil {
		result.Connections = *s.Connections
	}
	if s.Rate != nil {
		result.Rate = *s.Rate
	}
	if s.RatePer != nil {
		period, err := time.ParseDuration(*s.RatePer)
		if err != nil || period <= 0 {
			return Limits{}, errors.New("traffic rate period must be a positive duration")
		}
		result.RatePer = period
	}
	if s.Burst != nil {
		result.Burst = *s.Burst
	}
	if s.UploadBytes != nil {
		result.UploadBytes = *s.UploadBytes
	}
	if s.DownloadBytes != nil {
		result.DownloadBytes = *s.DownloadBytes
	}
	if !result.Valid() {
		return Limits{}, errors.New("traffic connections, rate, burst, and bandwidth must be positive")
	}
	if result.Connections > ceiling.Connections {
		return Limits{}, fmt.Errorf("traffic connections %d exceed server ceiling %d", result.Connections, ceiling.Connections)
	}
	if !rateWithin(result, ceiling) {
		return Limits{}, fmt.Errorf("traffic new-connection rate %d/%s exceeds server ceiling %d/%s", result.Rate, result.period(), ceiling.Rate, ceiling.period())
	}
	if result.Burst > ceiling.Burst {
		return Limits{}, fmt.Errorf("traffic connection burst %d exceeds server ceiling %d", result.Burst, ceiling.Burst)
	}
	if result.UploadBytes > ceiling.UploadBytes || result.DownloadBytes > ceiling.DownloadBytes {
		return Limits{}, fmt.Errorf("traffic bandwidth exceeds server ceiling: upload %d B/s, download %d B/s", ceiling.UploadBytes, ceiling.DownloadBytes)
	}
	return result, nil
}

func (l Limits) period() time.Duration {
	if l.RatePer == 0 {
		return time.Second
	}
	return l.RatePer
}

func (l Limits) Within(ceiling Limits) bool {
	return l.Valid() && ceiling.Valid() && l.Connections <= ceiling.Connections &&
		rateWithin(l, ceiling) && l.Burst <= ceiling.Burst &&
		l.UploadBytes <= ceiling.UploadBytes && l.DownloadBytes <= ceiling.DownloadBytes
}

func rateWithin(selected, ceiling Limits) bool {
	actualHigh, actualLow := bits.Mul64(uint64(selected.Rate), uint64(ceiling.period()))
	maximumHigh, maximumLow := bits.Mul64(uint64(ceiling.Rate), uint64(selected.period()))
	return actualHigh < maximumHigh || actualHigh == maximumHigh && actualLow <= maximumLow
}
