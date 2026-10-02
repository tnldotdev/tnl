package benchworkload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	BandwidthDownstream    = "downstream"
	BandwidthUpstream      = "upstream"
	BandwidthBidirectional = "bidirectional"

	bandwidthPath                 = "/bandwidth"
	bandwidthRequestDurationLimit = time.Hour
	bandwidthRequestGrace         = 5 * time.Second
	bandwidthCompletionGrace      = time.Second
	bandwidthChunkBytes           = 32 << 10
	maxBandwidthStreams           = 4096
	maxBandwidthRate              = int64(1 << 40)
	maxBandwidthStreamRate        = int64(1 << 30)
	maxBandwidthDuration          = 24 * time.Hour
)

// ErrBandwidthLate identifies a complete transfer that missed its deadline.
var ErrBandwidthLate = errors.New("bandwidth completed after its deadline")

const (
	bandwidthDirectionHeader = "X-TNL-Bench-Direction"
	bandwidthRateHeader      = "X-TNL-Bench-Bytes-Per-Second"
	bandwidthDurationHeader  = "X-TNL-Bench-Duration-Nanoseconds"
	bandwidthBytesHeader     = "X-TNL-Bench-Bytes"
)

// BandwidthConfig describes a fixed-rate transfer phase. Streams is the
// number of streams per active direction.
type BandwidthConfig struct {
	Direction      string        `json:"direction"`
	Streams        int           `json:"streams_per_direction"`
	BytesPerSecond int64         `json:"bytes_per_second_per_direction"`
	Start          time.Time     `json:"start"`
	Duration       time.Duration `json:"duration"`
}

// BandwidthResult records exact application bytes transferred by a phase.
type BandwidthResult struct {
	Direction              string                  `json:"direction"`
	StreamsPerDirection    int                     `json:"streams_per_direction"`
	TargetBytesPerSecond   int64                   `json:"target_bytes_per_second_per_direction"`
	SetupDuration          time.Duration           `json:"setup_duration,omitempty"`
	TargetDuration         time.Duration           `json:"target_duration"`
	StartedAt              time.Time               `json:"started_at"`
	Elapsed                time.Duration           `json:"elapsed"`
	ExpectedUploadBytes    int64                   `json:"expected_upload_bytes"`
	UploadBytes            int64                   `json:"upload_bytes"`
	ExpectedDownloadBytes  int64                   `json:"expected_download_bytes"`
	DownloadBytes          int64                   `json:"download_bytes"`
	UploadBytesPerSecond   float64                 `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond float64                 `json:"download_bytes_per_second"`
	Failures               int                     `json:"failures"`
	FailureSamples         []string                `json:"failure_samples,omitempty"`
	Streams                []BandwidthStreamResult `json:"streams,omitempty"`
	PerSecond              []BandwidthSecond       `json:"per_second,omitempty"`
}

type BandwidthStreamResult struct {
	Index          int           `json:"index"`
	URL            string        `json:"url"`
	Direction      string        `json:"direction"`
	ExpectedBytes  int64         `json:"expected_bytes"`
	Bytes          int64         `json:"bytes"`
	FirstByteDelay time.Duration `json:"first_byte_delay,omitempty"`
	LastByteDelay  time.Duration `json:"last_byte_delay,omitempty"`
	Error          string        `json:"error,omitempty"`
}

type BandwidthSecond struct {
	Second        int   `json:"second"`
	UploadBytes   int64 `json:"upload_bytes"`
	DownloadBytes int64 `json:"download_bytes"`
}

type bandwidthBuckets struct {
	upload   []atomic.Int64
	download []atomic.Int64
}

func newBandwidthBuckets(duration time.Duration) *bandwidthBuckets {
	count := int(duration/time.Second) + int(bandwidthRequestGrace/time.Second) + 2
	return &bandwidthBuckets{upload: make([]atomic.Int64, count), download: make([]atomic.Int64, count)}
}

func (b *bandwidthBuckets) observe(direction string, at time.Duration, bytes int) {
	index := min(max(int(at/time.Second), 0), len(b.upload)-1)
	if direction == BandwidthUpstream {
		b.upload[index].Add(int64(bytes))
	} else {
		b.download[index].Add(int64(bytes))
	}
}

func (b *bandwidthBuckets) snapshot(duration time.Duration) []BandwidthSecond {
	count := min(int(duration/time.Second)+1, len(b.upload))
	seconds := make([]BandwidthSecond, count)
	for index := range seconds {
		seconds[index] = BandwidthSecond{Second: index, UploadBytes: b.upload[index].Load(), DownloadBytes: b.download[index].Load()}
	}
	return seconds
}

type bandwidthProgress struct {
	start, first, last time.Time
	direction          string
	buckets            *bandwidthBuckets
}

func (p *bandwidthProgress) observe(bytes int) {
	if bytes <= 0 {
		return
	}
	now := time.Now()
	if p.first.IsZero() {
		p.first = now
	}
	p.last = now
	p.buckets.observe(p.direction, now.Sub(p.start), bytes)
}

type bandwidthStream struct {
	client    *http.Client
	transport *http.Transport
	url       string
	direction string
	rate      int64
}

// BandwidthSession owns one verified, reusable visitor connection per stream.
// prepare it before setting the measurement start time.
type BandwidthSession struct {
	streams        []bandwidthStream
	direction      string
	perDirection   int
	bytesPerSecond int64
	setupDuration  time.Duration
}

func (s *BandwidthSession) Close() {
	for _, stream := range s.streams {
		if stream.transport != nil {
			stream.transport.CloseIdleConnections()
		}
	}
}

// PrepareBandwidth establishes and verifies visitor TLS before measurement.
func (v Visitor) PrepareBandwidth(ctx context.Context, direction string, streams int, bytesPerSecond int64, urls []string) (*BandwidthSession, error) {
	if err := validateBandwidthShape(direction, streams, bytesPerSecond, urls); err != nil {
		return nil, err
	}
	started := time.Now()
	session := &BandwidthSession{direction: direction, perDirection: streams, bytesPerSecond: bytesPerSecond}
	directions := []string{direction}
	if direction == BandwidthBidirectional {
		directions = []string{BandwidthDownstream, BandwidthUpstream}
	}
	session.streams = make([]bandwidthStream, len(directions)*streams)
	errorsByStream := make([]error, len(session.streams))
	var workers sync.WaitGroup
	parallel := make(chan struct{}, 64)
	for directionIndex, name := range directions {
		for worker := range streams {
			index := directionIndex*streams + worker
			parallel <- struct{}{}
			workers.Go(func() {
				defer func() { <-parallel }()
				client, transport := v.bandwidthClient()
				session.streams[index] = bandwidthStream{client: client, transport: transport, url: urls[worker%len(urls)], direction: name,
					rate: assignment64(bytesPerSecond, streams, worker)}
				errorsByStream[index] = prepareBandwidthConnection(ctx, client, session.streams[index].url)
			})
		}
	}
	workers.Wait()
	for index, err := range errorsByStream {
		if err != nil {
			session.Close()
			return nil, fmt.Errorf("prepare bandwidth stream %d: %w", index, err)
		}
	}
	session.setupDuration = time.Since(started)
	return session, nil
}

func prepareBandwidthConnection(ctx context.Context, client *http.Client, rawURL string) error {
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		return errors.New("bandwidth URL must be an HTTPS origin")
	}
	endpoint.Path, endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "/bench", "", "", ""
	probeCtx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodHead, endpoint.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("bandwidth setup: HTTP %d", response.StatusCode)
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return errors.New("bandwidth setup: visitor TLS was not verified")
	}
	if response.Header.Get("X-TNL-Bench-Host") != endpoint.Host {
		return errors.New("bandwidth setup: local service observed the wrong hostname")
	}
	return nil
}

// CorrectnessErr reports missing, corrupted, or failed transfers without
// classifying a complete but late transfer as lost data.
func (r BandwidthResult) CorrectnessErr() error {
	if r.Failures != 0 {
		return fmt.Errorf("%d bandwidth transfers failed", r.Failures)
	}
	if r.UploadBytes != r.ExpectedUploadBytes {
		return fmt.Errorf("uploaded %d bytes, want %d", r.UploadBytes, r.ExpectedUploadBytes)
	}
	if r.DownloadBytes != r.ExpectedDownloadBytes {
		return fmt.Errorf("downloaded %d bytes, want %d", r.DownloadBytes, r.ExpectedDownloadBytes)
	}
	return nil
}

// Err reports incomplete or late transfers.
func (r BandwidthResult) Err() error {
	if err := r.CorrectnessErr(); err != nil {
		return err
	}
	if r.TargetDuration > 0 && r.Elapsed > r.TargetDuration+bandwidthCompletionGrace {
		return fmt.Errorf("bandwidth completed in %s, target duration %s with %s grace: %w", r.Elapsed, r.TargetDuration, bandwidthCompletionGrace, ErrBandwidthLate)
	}
	return nil
}

// Bandwidth runs paced, byte-verified transfers against the supplied URLs.
func (v Visitor) Bandwidth(ctx context.Context, config BandwidthConfig, urls []string) (BandwidthResult, error) {
	result := BandwidthResult{
		Direction:            config.Direction,
		StreamsPerDirection:  config.Streams,
		TargetBytesPerSecond: config.BytesPerSecond,
		TargetDuration:       config.Duration,
		StartedAt:            config.Start,
	}
	if err := validateBandwidthConfig(config, urls); err != nil {
		return result, err
	}
	session, err := v.PrepareBandwidth(ctx, config.Direction, config.Streams, config.BytesPerSecond, urls)
	if err != nil {
		return result, err
	}
	defer session.Close()
	return session.Run(ctx, config.Start, config.Duration)
}

// Run measures prepared streams against one common start time.
func (s *BandwidthSession) Run(ctx context.Context, start time.Time, duration time.Duration) (BandwidthResult, error) {
	return s.runWithSegmentDuration(ctx, start, duration, bandwidthRequestDurationLimit)
}

func (s *BandwidthSession) runWithSegmentDuration(ctx context.Context, start time.Time, duration, segmentDuration time.Duration) (BandwidthResult, error) {
	result := BandwidthResult{Direction: s.direction, StreamsPerDirection: s.perDirection, TargetBytesPerSecond: s.bytesPerSecond,
		SetupDuration: s.setupDuration, TargetDuration: duration, StartedAt: start}
	if start.IsZero() || duration <= 0 || duration > maxBandwidthDuration || segmentDuration <= 0 {
		return result, errors.New("invalid bandwidth start or duration")
	}
	buckets := newBandwidthBuckets(duration)

	type transferResult struct {
		direction string
		expected  int64
		bytes     int64
		err       error
		stream    BandwidthStreamResult
	}
	results := make(chan transferResult, len(s.streams))
	var workers sync.WaitGroup
	for index, stream := range s.streams {
		workers.Go(func() {
			progress := &bandwidthProgress{start: start, direction: stream.direction, buckets: buckets}
			expected, transferred, err := stream.run(ctx, start, duration, segmentDuration, progress)
			observation := BandwidthStreamResult{Index: index, URL: stream.url, Direction: stream.direction, ExpectedBytes: expected, Bytes: transferred}
			if !progress.first.IsZero() {
				observation.FirstByteDelay = progress.first.Sub(start)
				observation.LastByteDelay = progress.last.Sub(start)
			}
			if err != nil {
				observation.Error = err.Error()
			}
			results <- transferResult{direction: stream.direction, expected: expected, bytes: transferred, err: err, stream: observation}
		})
	}
	workers.Wait()
	close(results)
	result.Elapsed = max(time.Since(start), 0)
	result.Streams = make([]BandwidthStreamResult, len(s.streams))
	for transfer := range results {
		result.Streams[transfer.stream.Index] = transfer.stream
		if transfer.direction == BandwidthUpstream {
			result.ExpectedUploadBytes += transfer.expected
			result.UploadBytes += transfer.bytes
		} else {
			result.ExpectedDownloadBytes += transfer.expected
			result.DownloadBytes += transfer.bytes
		}
		if transfer.err != nil {
			result.Failures++
			if len(result.FailureSamples) < 8 {
				result.FailureSamples = append(result.FailureSamples, transfer.err.Error())
			}
		}
	}
	if seconds := result.Elapsed.Seconds(); seconds > 0 {
		result.UploadBytesPerSecond = float64(result.UploadBytes) / seconds
		result.DownloadBytesPerSecond = float64(result.DownloadBytes) / seconds
	}
	result.PerSecond = buckets.snapshot(max(duration, result.Elapsed))
	return result, result.Err()
}

func validateBandwidthShape(direction string, streams int, bytesPerSecond int64, urls []string) error {
	if direction != BandwidthDownstream && direction != BandwidthUpstream && direction != BandwidthBidirectional {
		return errors.New("bandwidth direction must be downstream, upstream, or bidirectional")
	}
	if streams < 1 || streams > maxBandwidthStreams {
		return errors.New("bandwidth streams are out of range")
	}
	if bytesPerSecond < int64(streams) || bytesPerSecond > maxBandwidthRate || bytesPerSecond > int64(streams)*maxBandwidthStreamRate {
		return errors.New("bandwidth bytes per second are out of range")
	}
	if len(urls) == 0 {
		return errors.New("bandwidth URLs are required")
	}
	return nil
}

func validateBandwidthConfig(config BandwidthConfig, urls []string) error {
	if err := validateBandwidthShape(config.Direction, config.Streams, config.BytesPerSecond, urls); err != nil {
		return err
	}
	if config.Start.IsZero() {
		return errors.New("bandwidth start is required")
	}
	if config.Duration <= 0 || config.Duration > maxBandwidthDuration {
		return errors.New("bandwidth duration is out of range")
	}
	return nil
}

func (s bandwidthStream) run(ctx context.Context, start time.Time, duration, segmentDuration time.Duration, progress *bandwidthProgress) (int64, int64, error) {
	var expected, transferred int64
	end := start.Add(duration)
	for segmentStart := start; segmentStart.Before(end); segmentStart = segmentStart.Add(segmentDuration) {
		length := min(segmentDuration, end.Sub(segmentStart))
		if err := WaitUntil(ctx, segmentStart); err != nil {
			return expected, transferred, err
		}
		segmentExpected := bytesForDuration(s.rate, length)
		expected += segmentExpected
		segmentBytes, err := s.request(ctx, length, segmentExpected, progress)
		transferred += segmentBytes
		if err != nil {
			return expected, transferred, err
		}
	}
	return expected, transferred, nil
}

func (s bandwidthStream) request(ctx context.Context, duration time.Duration, expected int64, progress *bandwidthProgress) (int64, error) {
	endpoint, err := url.Parse(s.url)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		return 0, errors.New("bandwidth URL must be an HTTPS origin")
	}
	expectedHost := endpoint.Host
	endpoint.Path = bandwidthPath
	endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "", "", ""
	requestCtx, cancel := context.WithTimeout(ctx, duration+bandwidthRequestGrace)
	defer cancel()
	method := http.MethodGet
	var body io.Reader
	var paced *pacedPayloadReader
	if s.direction == BandwidthUpstream {
		method = http.MethodPost
		paced = newPacedPayloadReader(requestCtx, s.rate, expected)
		paced.observe = progress.observe
		body = paced
	}
	request, err := http.NewRequestWithContext(requestCtx, method, endpoint.String(), body)
	if err != nil {
		return 0, err
	}
	request.Header.Set(bandwidthDirectionHeader, s.direction)
	request.Header.Set(bandwidthRateHeader, strconv.FormatInt(s.rate, 10))
	request.Header.Set(bandwidthDurationHeader, strconv.FormatInt(duration.Nanoseconds(), 10))
	if paced != nil {
		request.ContentLength = expected
	}
	response, err := s.client.Do(request)
	if err != nil {
		if paced != nil {
			return paced.Bytes(), err
		}
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		if paced != nil {
			return paced.Bytes(), fmt.Errorf("unverified bandwidth response: status %d", response.StatusCode)
		}
		return 0, fmt.Errorf("unverified bandwidth response: status %d", response.StatusCode)
	}
	if response.Header.Get("X-TNL-Bench-Host") != expectedHost {
		return 0, errors.New("bandwidth response host mismatch")
	}
	if s.direction == BandwidthUpstream {
		actual, err := strconv.ParseInt(response.Header.Get(bandwidthBytesHeader), 10, 64)
		if err != nil || actual != expected {
			return paced.Bytes(), errors.New("bandwidth upload acknowledgement mismatch")
		}
		return paced.Bytes(), nil
	}
	verifier := payloadVerifier{observe: progress.observe}
	_, err = io.Copy(&verifier, response.Body)
	if err != nil {
		return verifier.Bytes(), err
	}
	if verifier.Bytes() != expected {
		return verifier.Bytes(), fmt.Errorf("bandwidth response bytes %d, want %d", verifier.Bytes(), expected)
	}
	return verifier.Bytes(), nil
}

type pacedPayloadReader struct {
	ctx     context.Context
	rate    int64
	total   int64
	read    int64
	start   time.Time
	observe func(int)
}

func newPacedPayloadReader(ctx context.Context, rate, total int64) *pacedPayloadReader {
	return &pacedPayloadReader{ctx: ctx, rate: rate, total: total}
}

func (r *pacedPayloadReader) Read(buffer []byte) (int, error) {
	if r.read == r.total {
		return 0, io.EOF
	}
	if r.start.IsZero() {
		r.start = time.Now()
	}
	chunk := min(int64(len(buffer)), int64(bandwidthChunkBytes), max(r.rate/100, 1), r.total-r.read)
	if err := WaitUntil(r.ctx, r.start.Add(durationForBytes(r.read+chunk, r.rate))); err != nil {
		return 0, err
	}
	for index := range int(chunk) {
		buffer[index] = byte(r.read + int64(index))
	}
	r.read += chunk
	if r.observe != nil {
		r.observe(int(chunk))
	}
	return int(chunk), nil
}

func (r *pacedPayloadReader) Bytes() int64 { return r.read }

type payloadVerifier struct {
	bytes   int64
	observe func(int)
}

func (v *payloadVerifier) Write(buffer []byte) (int, error) {
	for index, value := range buffer {
		if value != byte(v.bytes+int64(index)) {
			return index, fmt.Errorf("bandwidth payload mismatch at byte %d", v.bytes+int64(index))
		}
	}
	v.bytes += int64(len(buffer))
	if v.observe != nil {
		v.observe(len(buffer))
	}
	return len(buffer), nil
}

func (v *payloadVerifier) Bytes() int64 { return v.bytes }

func assignment64(total int64, workers, index int) int64 {
	base, remainder := total/int64(workers), total%int64(workers)
	if int64(index) < remainder {
		return base + 1
	}
	return base
}

func bytesForDuration(rate int64, duration time.Duration) int64 {
	seconds, remainder := duration/time.Second, duration%time.Second
	return rate*int64(seconds) + rate*int64(remainder)/int64(time.Second)
}

func durationForBytes(bytes, rate int64) time.Duration {
	return time.Duration(float64(bytes) / float64(rate) * float64(time.Second))
}
