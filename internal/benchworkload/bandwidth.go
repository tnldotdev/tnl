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
	"time"
)

const (
	BandwidthDownstream    = "downstream"
	BandwidthUpstream      = "upstream"
	BandwidthBidirectional = "bidirectional"

	bandwidthPath            = "/bandwidth"
	bandwidthSegmentDuration = 20 * time.Second
	bandwidthRequestGrace    = 5 * time.Second
	bandwidthCompletionGrace = time.Second
	bandwidthChunkBytes      = 32 << 10
	maxBandwidthStreams      = 4096
	maxBandwidthRate         = int64(1 << 40)
	maxBandwidthStreamRate   = int64(1 << 30)
	maxBandwidthDuration     = 24 * time.Hour
)

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
	Direction              string        `json:"direction"`
	StreamsPerDirection    int           `json:"streams_per_direction"`
	TargetBytesPerSecond   int64         `json:"target_bytes_per_second_per_direction"`
	TargetDuration         time.Duration `json:"target_duration"`
	StartedAt              time.Time     `json:"started_at"`
	Elapsed                time.Duration `json:"elapsed"`
	ExpectedUploadBytes    int64         `json:"expected_upload_bytes"`
	UploadBytes            int64         `json:"upload_bytes"`
	ExpectedDownloadBytes  int64         `json:"expected_download_bytes"`
	DownloadBytes          int64         `json:"download_bytes"`
	UploadBytesPerSecond   float64       `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond float64       `json:"download_bytes_per_second"`
	Failures               int           `json:"failures"`
	FailureSamples         []string      `json:"failure_samples,omitempty"`
}

// Err reports incomplete or failed transfers.
func (r BandwidthResult) Err() error {
	if r.Failures != 0 {
		return fmt.Errorf("%d bandwidth transfers failed", r.Failures)
	}
	if r.UploadBytes != r.ExpectedUploadBytes {
		return fmt.Errorf("uploaded %d bytes, want %d", r.UploadBytes, r.ExpectedUploadBytes)
	}
	if r.DownloadBytes != r.ExpectedDownloadBytes {
		return fmt.Errorf("downloaded %d bytes, want %d", r.DownloadBytes, r.ExpectedDownloadBytes)
	}
	if r.TargetDuration > 0 && r.Elapsed > r.TargetDuration+bandwidthCompletionGrace {
		return fmt.Errorf("bandwidth completed in %s, target duration %s with %s grace", r.Elapsed, r.TargetDuration, bandwidthCompletionGrace)
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
	directions := []string{config.Direction}
	if config.Direction == BandwidthBidirectional {
		directions = []string{BandwidthDownstream, BandwidthUpstream}
	}

	type transferResult struct {
		direction string
		expected  int64
		bytes     int64
		err       error
	}
	results := make(chan transferResult, len(directions)*config.Streams)
	var workers sync.WaitGroup
	for _, direction := range directions {
		for worker := range config.Streams {
			rate := assignment64(config.BytesPerSecond, config.Streams, worker)
			workers.Add(1)
			go func(direction string, worker int, rate int64) {
				defer workers.Done()
				expected, transferred, err := v.runBandwidthStream(ctx, urls[worker%len(urls)], direction, rate, config.Start, config.Duration)
				results <- transferResult{direction: direction, expected: expected, bytes: transferred, err: err}
			}(direction, worker, rate)
		}
	}
	workers.Wait()
	close(results)
	result.Elapsed = max(time.Since(config.Start), 0)
	for transfer := range results {
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
	return result, result.Err()
}

func validateBandwidthConfig(config BandwidthConfig, urls []string) error {
	if config.Direction != BandwidthDownstream && config.Direction != BandwidthUpstream && config.Direction != BandwidthBidirectional {
		return errors.New("bandwidth direction must be downstream, upstream, or bidirectional")
	}
	if config.Streams < 1 || config.Streams > maxBandwidthStreams {
		return errors.New("bandwidth streams are out of range")
	}
	if config.BytesPerSecond < int64(config.Streams) || config.BytesPerSecond > maxBandwidthRate || config.BytesPerSecond > int64(config.Streams)*maxBandwidthStreamRate {
		return errors.New("bandwidth bytes per second are out of range")
	}
	if config.Start.IsZero() {
		return errors.New("bandwidth start is required")
	}
	if config.Duration <= 0 || config.Duration > maxBandwidthDuration {
		return errors.New("bandwidth duration is out of range")
	}
	if len(urls) == 0 {
		return errors.New("bandwidth URLs are required")
	}
	return nil
}

func (v Visitor) runBandwidthStream(ctx context.Context, rawURL, direction string, rate int64, start time.Time, duration time.Duration) (int64, int64, error) {
	var expected, transferred int64
	end := start.Add(duration)
	for segmentStart := start; segmentStart.Before(end); segmentStart = segmentStart.Add(bandwidthSegmentDuration) {
		segmentDuration := min(bandwidthSegmentDuration, end.Sub(segmentStart))
		if err := WaitUntil(ctx, segmentStart); err != nil {
			return expected, transferred, err
		}
		segmentExpected := bytesForDuration(rate, segmentDuration)
		expected += segmentExpected
		segmentBytes, err := v.runBandwidthRequest(ctx, rawURL, direction, rate, segmentDuration, segmentExpected)
		transferred += segmentBytes
		if err != nil {
			return expected, transferred, err
		}
	}
	return expected, transferred, nil
}

func (v Visitor) runBandwidthRequest(ctx context.Context, rawURL, direction string, rate int64, duration time.Duration, expected int64) (int64, error) {
	endpoint, err := url.Parse(rawURL)
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
	if direction == BandwidthUpstream {
		method = http.MethodPost
		paced = newPacedPayloadReader(requestCtx, rate, expected)
		body = paced
	}
	request, err := http.NewRequestWithContext(requestCtx, method, endpoint.String(), body)
	if err != nil {
		return 0, err
	}
	request.Header.Set(bandwidthDirectionHeader, direction)
	request.Header.Set(bandwidthRateHeader, strconv.FormatInt(rate, 10))
	request.Header.Set(bandwidthDurationHeader, strconv.FormatInt(duration.Nanoseconds(), 10))
	if paced != nil {
		request.ContentLength = expected
	}
	client, transport := v.client()
	defer transport.CloseIdleConnections()
	response, err := client.Do(request)
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
	if direction == BandwidthUpstream {
		actual, err := strconv.ParseInt(response.Header.Get(bandwidthBytesHeader), 10, 64)
		if err != nil || actual != expected {
			return paced.Bytes(), errors.New("bandwidth upload acknowledgement mismatch")
		}
		return paced.Bytes(), nil
	}
	verifier := payloadVerifier{}
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
	ctx   context.Context
	rate  int64
	total int64
	read  int64
	start time.Time
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
	return int(chunk), nil
}

func (r *pacedPayloadReader) Bytes() int64 { return r.read }

type payloadVerifier struct{ bytes int64 }

func (v *payloadVerifier) Write(buffer []byte) (int, error) {
	for index, value := range buffer {
		if value != byte(v.bytes+int64(index)) {
			return index, fmt.Errorf("bandwidth payload mismatch at byte %d", v.bytes+int64(index))
		}
	}
	v.bytes += int64(len(buffer))
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
