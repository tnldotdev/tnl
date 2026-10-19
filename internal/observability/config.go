package observability

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"go.opentelemetry.io/otel/attribute"
)

// Config contains only export settings. no endpoint means no network export.
// resource attributes are fixed process facts, never a current request's tenant.
type Config struct {
	Metrics, Traces      SignalConfig
	ServiceName          string
	Resource             []attribute.KeyValue
	Interval             time.Duration
	QueueSize, BatchSize int
	BatchDelay           time.Duration
	SampleRatio          float64
	Sampler              string
	Disabled             bool
	processOwner         bool
}

type SignalConfig struct {
	Endpoint string
	Headers  map[string]string
	Timeout  time.Duration
	TLS      *tls.Config
	Gzip     bool
}

func (Config) String() string         { return "observability configuration" }
func (Config) GoString() string       { return "observability configuration" }
func (SignalConfig) String() string   { return "observability signal configuration" }
func (SignalConfig) GoString() string { return "observability signal configuration" }

// ConfigFromEnv accepts the standard OTLP/HTTP configuration subset documented
// in metrics.md. errors include only the setting name, never its input value.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := Config{ServiceName: getenv("OTEL_SERVICE_NAME"), Interval: 60 * time.Second, QueueSize: 2048, BatchSize: 512, BatchDelay: 5 * time.Second, SampleRatio: 1}
	if getenv("OTEL_SDK_DISABLED") == "true" {
		c.Disabled = true
		return c, nil
	}
	var err error
	c.Metrics, err = signalConfig(getenv, "METRICS", "metrics")
	if err != nil {
		return Config{}, err
	}
	c.Traces, err = signalConfig(getenv, "TRACES", "traces")
	if err != nil {
		return Config{}, err
	}
	for _, spec := range []struct {
		key               string
		dest              *time.Duration
		fallback, maximum time.Duration
	}{
		{"OTEL_METRIC_EXPORT_INTERVAL", &c.Interval, 60 * time.Second, 10 * time.Minute},
		{"OTEL_BSP_SCHEDULE_DELAY", &c.BatchDelay, 5 * time.Second, time.Minute},
	} {
		*spec.dest, err = milliseconds(getenv(spec.key), spec.fallback, spec.maximum)
		if err != nil {
			return Config{}, settingError(spec.key)
		}
	}
	for _, spec := range []struct {
		key     string
		dest    *int
		maximum int
	}{
		{"OTEL_BSP_MAX_QUEUE_SIZE", &c.QueueSize, 8192}, {"OTEL_BSP_MAX_EXPORT_BATCH_SIZE", &c.BatchSize, 1024},
	} {
		if value := getenv(spec.key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 || n > spec.maximum {
				return Config{}, settingError(spec.key)
			}
			*spec.dest = n
		}
	}
	if c.BatchSize > c.QueueSize {
		c.BatchSize = c.QueueSize
	}
	c.Sampler = getenv("OTEL_TRACES_SAMPLER")
	switch c.Sampler {
	case "", "always_on", "parentbased_always_on":
	case "always_off", "parentbased_always_off":
		c.SampleRatio = 0
	case "traceidratio", "parentbased_traceidratio":
		ratio, err := strconv.ParseFloat(getenv("OTEL_TRACES_SAMPLER_ARG"), 64)
		if err != nil || !(ratio >= 0 && ratio <= 1) {
			return Config{}, settingError("OTEL_TRACES_SAMPLER_ARG")
		}
		c.SampleRatio = ratio
	default:
		return Config{}, settingError("OTEL_TRACES_SAMPLER")
	}
	if len(c.ServiceName) > 128 || strings.ContainsAny(c.ServiceName, "\r\n") {
		return Config{}, settingError("OTEL_SERVICE_NAME")
	}
	if raw := getenv("OTEL_RESOURCE_ATTRIBUTES"); raw != "" {
		for _, entry := range strings.Split(raw, ",") {
			key, value, ok := strings.Cut(entry, "=")
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			if !ok || len(value) > 128 || strings.ContainsAny(value, "\r\n") {
				return Config{}, settingError("OTEL_RESOURCE_ATTRIBUTES")
			}
			switch key {
			case "service.name":
				if getenv("OTEL_SERVICE_NAME") == "" {
					c.ServiceName = value
				}
			case "service.instance.id", "service.namespace", "deployment.environment.name", "cloud.provider", "cloud.region", "cloud.availability_zone":
				c.Resource = append(c.Resource, attribute.String(key, value))
			default:
				return Config{}, settingError("OTEL_RESOURCE_ATTRIBUTES")
			}
		}
	}
	return c, nil
}

func signalConfig(getenv func(string) string, signal, path string) (SignalConfig, error) {
	c := SignalConfig{Timeout: 5 * time.Second}
	prefix := "OTEL_EXPORTER_OTLP_" + signal + "_"
	selected := func(suffix string) string {
		if value := getenv(prefix + suffix); value != "" {
			return value
		}
		return getenv("OTEL_EXPORTER_OTLP_" + suffix)
	}
	switch getenv("OTEL_" + signal + "_EXPORTER") {
	case "none":
		return c, nil
	case "", "otlp":
	default:
		return c, settingError("OTEL_" + signal + "_EXPORTER")
	}
	c.Endpoint = getenv(prefix + "ENDPOINT")
	if c.Endpoint == "" {
		if base := getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); base != "" {
			c.Endpoint = strings.TrimRight(base, "/") + "/v1/" + path
		}
	}
	if c.Endpoint == "" {
		return c, nil
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return c, settingError(prefix + "ENDPOINT")
	}
	if protocol := selected("PROTOCOL"); protocol != "" && protocol != "http/protobuf" {
		return c, settingError(prefix + "PROTOCOL")
	}
	if selected("INSECURE") != "" && selected("INSECURE") != "false" {
		return c, settingError(prefix + "INSECURE")
	}
	c.Timeout, err = milliseconds(selected("TIMEOUT"), 5*time.Second, 10*time.Second)
	if err != nil {
		return c, settingError(prefix + "TIMEOUT")
	}
	// the periodic reader and batch processor may shorten the exporter timeout.
	for _, key := range map[string][]string{"METRICS": {"OTEL_METRIC_EXPORT_TIMEOUT"}, "TRACES": {"OTEL_BSP_EXPORT_TIMEOUT"}}[signal] {
		if value := getenv(key); value != "" {
			d, err := milliseconds(value, c.Timeout, 10*time.Second)
			if err != nil {
				return c, settingError(key)
			}
			c.Timeout = min(c.Timeout, d)
		}
	}
	c.Headers = make(map[string]string)
	if raw := selected("HEADERS"); raw != "" {
		if len(raw) > 8192 {
			return c, settingError(prefix + "HEADERS")
		}
		for _, pair := range strings.Split(raw, ",") {
			key, value, ok := strings.Cut(pair, "=")
			key = strings.TrimSpace(key)
			value, err = url.PathUnescape(strings.TrimSpace(value))
			if !ok || err != nil || key == "" || strings.ContainsAny(key, " \t\r\n:") || strings.ContainsAny(value, "\r\n") {
				return c, settingError(prefix + "HEADERS")
			}
			c.Headers[key] = value
		}
	}
	switch selected("COMPRESSION") {
	case "", "none":
	case "gzip":
		c.Gzip = true
	default:
		return c, settingError(prefix + "COMPRESSION")
	}
	c.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	if path := selected("CERTIFICATE"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return c, settingError(prefix + "CERTIFICATE")
		}
		c.TLS.RootCAs = x509.NewCertPool()
		if !c.TLS.RootCAs.AppendCertsFromPEM(pem) {
			return c, settingError(prefix + "CERTIFICATE")
		}
	}
	cert, key := selected("CLIENT_CERTIFICATE"), selected("CLIENT_KEY")
	if cert != "" || key != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return c, settingError(prefix + "CLIENT_CERTIFICATE")
		}
		c.TLS.Certificates = []tls.Certificate{pair}
	}
	return c, nil
}

func milliseconds(raw string, fallback, maximum time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 || n > maximum.Milliseconds() {
		return 0, errors.New("invalid duration")
	}
	return time.Duration(n) * time.Millisecond, nil
}
func settingError(key string) error {
	return failure.WrapSetting("configure observability", failure.ObservabilityConfigInvalid, failure.Setting(key), fmt.Errorf("invalid %s observability setting", key))
}

func (s SignalConfig) client() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = s.TLS
	transport.MaxConnsPerHost = 2
	transport.MaxIdleConnsPerHost = 2
	transport.ResponseHeaderTimeout = s.Timeout
	return &http.Client{Timeout: s.Timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
