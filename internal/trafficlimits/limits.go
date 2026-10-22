// package trafficlimits defines process-local encrypted visitor traffic budgets.
package trafficlimits

import (
	"errors"
	"math/bits"
	"regexp"
	"strconv"
	"time"
)

const ByteRatePattern = `^[1-9][0-9]*(KiB|MiB|GiB)/s$`

var byteRatePattern = regexp.MustCompile(ByteRatePattern)

// Limits belongs to one exact public URL and publish run, independently on each
// ingress process. zero totals mean unlimited; rates count encrypted bytes.
type Limits struct {
	Connections        int           `json:"connections"`
	Rate               int           `json:"rate"`
	RatePer            time.Duration `json:"rate_per_ns"`
	Burst              int           `json:"burst"`
	UploadBytes        int64         `json:"upload_bytes"`
	DownloadBytes      int64         `json:"download_bytes"`
	TotalConnections   int64         `json:"total_connections,omitempty"`
	TotalUploadBytes   int64         `json:"total_upload_bytes,omitempty"`
	TotalDownloadBytes int64         `json:"total_download_bytes,omitempty"`
}

func Default() Limits {
	return Limits{Connections: 32, Rate: 20, RatePer: time.Second, Burst: 40,
		UploadBytes: 8 << 20, DownloadBytes: 16 << 20}
}

func Ceiling() Limits {
	return Limits{Connections: 128, Rate: 100, RatePer: time.Second, Burst: 200,
		UploadBytes: 64 << 20, DownloadBytes: 128 << 20}
}

func (l Limits) Period() time.Duration {
	if l.RatePer == 0 {
		return time.Second
	}
	return l.RatePer
}

func (l Limits) Valid() bool {
	return l.Connections > 0 && l.Connections <= 1<<20 && l.Rate > 0 && l.Rate <= 1<<31 &&
		l.Burst > 0 && l.Burst <= 1<<31 && l.Period() >= time.Millisecond && l.Period() <= 24*time.Hour &&
		l.UploadBytes >= 64<<10 && l.UploadBytes <= 1<<40 &&
		l.DownloadBytes >= 64<<10 && l.DownloadBytes <= 1<<40 &&
		l.TotalConnections >= 0 && l.TotalUploadBytes >= 0 && l.TotalDownloadBytes >= 0
}

func (l Limits) Within(c Limits) bool {
	hi, lo := bits.Mul64(uint64(l.Rate), uint64(c.Period()))
	ch, cl := bits.Mul64(uint64(c.Rate), uint64(l.Period()))
	return l.Valid() && c.Valid() && l.Connections <= c.Connections &&
		(hi < ch || hi == ch && lo <= cl) && l.Burst <= c.Burst &&
		l.UploadBytes <= c.UploadBytes && l.DownloadBytes <= c.DownloadBytes &&
		totalWithin(l.TotalConnections, c.TotalConnections) &&
		totalWithin(l.TotalUploadBytes, c.TotalUploadBytes) && totalWithin(l.TotalDownloadBytes, c.TotalDownloadBytes)
}

func totalWithin(value, ceiling int64) bool { return ceiling == 0 || value > 0 && value <= ceiling }

// Selection contains only explicitly selected values. control resolves it once
// at publish-run creation and persists the resolved result with that run.
type Selection struct {
	Connections        *int    `json:"connections,omitempty"`
	Rate               *int    `json:"rate,omitempty"`
	RatePer            *string `json:"rate_per,omitempty"`
	Burst              *int    `json:"burst,omitempty"`
	UploadBytes        *int64  `json:"upload_bytes,omitempty"`
	DownloadBytes      *int64  `json:"download_bytes,omitempty"`
	TotalConnections   *int64  `json:"total_connections,omitempty"`
	TotalUploadBytes   *int64  `json:"total_upload_bytes,omitempty"`
	TotalDownloadBytes *int64  `json:"total_download_bytes,omitempty"`
}

// Clone keeps omitted values and gives each selected value independent storage.
func (s *Selection) Clone() *Selection {
	if s == nil {
		return nil
	}
	return &Selection{
		Connections: copyOptional(s.Connections), Rate: copyOptional(s.Rate), RatePer: copyOptional(s.RatePer),
		Burst: copyOptional(s.Burst), UploadBytes: copyOptional(s.UploadBytes), DownloadBytes: copyOptional(s.DownloadBytes),
		TotalConnections: copyOptional(s.TotalConnections), TotalUploadBytes: copyOptional(s.TotalUploadBytes), TotalDownloadBytes: copyOptional(s.TotalDownloadBytes),
	}
}

func copyOptional[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func (s Selection) Validate() error {
	_, err := s.apply(Default())
	return err
}

func (s Selection) apply(l Limits) (Limits, error) {
	for _, pair := range []struct {
		from *int
		to   *int
	}{
		{s.Connections, &l.Connections}, {s.Rate, &l.Rate}, {s.Burst, &l.Burst},
	} {
		if pair.from != nil {
			*pair.to = *pair.from
		}
	}
	for _, pair := range []struct {
		from *int64
		to   *int64
	}{
		{s.UploadBytes, &l.UploadBytes}, {s.DownloadBytes, &l.DownloadBytes},
		{s.TotalConnections, &l.TotalConnections}, {s.TotalUploadBytes, &l.TotalUploadBytes},
		{s.TotalDownloadBytes, &l.TotalDownloadBytes},
	} {
		if pair.from != nil {
			*pair.to = *pair.from
		}
	}
	if s.RatePer != nil {
		period, err := time.ParseDuration(*s.RatePer)
		if err != nil || period <= 0 {
			return Limits{}, errors.New("traffic rate period must be between 1ms and 24h")
		}
		l.RatePer = period
	}
	if !l.Valid() {
		return Limits{}, errors.New("traffic limits are outside supported bounds")
	}
	l.RatePer = l.Period()
	return l, nil
}

func (s Selection) Resolve(defaults, ceiling Limits) (Limits, error) {
	if !defaults.Within(ceiling) {
		return Limits{}, errors.New("traffic defaults exceed operator ceilings")
	}
	l, err := s.apply(defaults)
	if err != nil {
		return Limits{}, err
	}
	if !l.Within(ceiling) {
		return Limits{}, errors.New("traffic selection exceeds operator ceilings")
	}
	return l, nil
}

func ParseByteRate(value string) (int64, error) {
	if !byteRatePattern.MatchString(value) {
		return 0, errors.New("byte rate must use positive KiB/s, MiB/s, or GiB/s")
	}
	amount, err := strconv.ParseInt(value[:len(value)-5], 10, 64)
	if err != nil {
		return 0, errors.New("byte rate is too large")
	}
	multiplier := map[string]int64{"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}[value[len(value)-5:len(value)-2]]
	if amount > (1<<40)/multiplier || amount*multiplier < 64<<10 {
		return 0, errors.New("byte rate must be between 64KiB/s and 1TiB/s")
	}
	return amount * multiplier, nil
}
