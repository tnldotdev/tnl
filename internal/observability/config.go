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
	Metrics, Traces, Logs      SignalConfig
	ServiceName                string
	Resource                   []attribute.KeyValue
	Interval                   time.Duration
	QueueSize, BatchSize       int
	BatchDelay                 time.Duration
	LogQueueSize, LogBatchSize int
	LogBatchDelay              time.Duration
	SampleRatio                float64
	Sampler                    string
	Disabled                   bool
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
	c := Config{ServiceName: getenv("OTEL_SERVICE_NAME"), Interval: 60 * time.Second, QueueSize: 2048, BatchSize: 512, BatchDelay: 5 * time.Second, LogQueueSize: 2048, LogBatchSize: 512, LogBatchDelay: time.Second, SampleRatio: 1}
	if strings.EqualFold(getenv("OTEL_SDK_DISABLED"), "true") {
		c.ServiceName = ""
		c.Disabled = true
		return c, nil
	}
	if err := validateSDKProviderEnvironment(getenv); err != nil {
		return Config{}, err
	}
	exporters, err := exporterSettingsFromEnv(getenv)
	if err != nil {
		return Config{}, err
	}
	c.Metrics, err = signalConfig(getenv, "METRICS", exporters[""], exporters["METRICS"])
	if err != nil {
		return Config{}, err
	}
	c.Traces, err = signalConfig(getenv, "TRACES", exporters[""], exporters["TRACES"])
	if err != nil {
		return Config{}, err
	}
	c.Logs, err = signalConfig(getenv, "LOGS", exporters[""], exporters["LOGS"])
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
		{"OTEL_BLRP_SCHEDULE_DELAY", &c.LogBatchDelay, time.Second, time.Minute},
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
		{"OTEL_BLRP_MAX_QUEUE_SIZE", &c.LogQueueSize, 8192}, {"OTEL_BLRP_MAX_EXPORT_BATCH_SIZE", &c.LogBatchSize, 1024},
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
	if c.LogBatchSize > c.LogQueueSize {
		c.LogBatchSize = c.LogQueueSize
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
	if !validServiceName(c.ServiceName) {
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
				if !validServiceName(value) {
					return Config{}, settingError("OTEL_RESOURCE_ATTRIBUTES")
				}
				if getenv("OTEL_SERVICE_NAME") == "" {
					c.ServiceName = value
				}
			case "service.namespace":
				if value != "tnl" {
					return Config{}, settingError("OTEL_RESOURCE_ATTRIBUTES")
				}
			case "service.instance.id", "deployment.environment.name", "cloud.provider", "cloud.region", "cloud.availability_zone":
				c.Resource = append(c.Resource, attribute.String(key, value))
			default:
				return Config{}, settingError("OTEL_RESOURCE_ATTRIBUTES")
			}
		}
	}
	return c, nil
}

// parse every exporter input before applying precedence, including generic values
// overridden by per-signal values. the pinned SDK reads them before its options.
func exporterSettingsFromEnv(getenv func(string) string) (map[string]exporterSettings, error) {
	settings := make(map[string]exporterSettings, 4)
	for _, signal := range []string{"", "METRICS", "TRACES", "LOGS"} {
		prefix := "OTEL_EXPORTER_OTLP_"
		if signal != "" {
			prefix += signal + "_"
		}
		parsed, err := parseExporterSettings(getenv, prefix)
		if err != nil {
			return nil, err
		}
		settings[signal] = parsed
	}
	for key, allowed := range map[string]string{
		"OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE":        "cumulative",
		"OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION": "explicit_bucket_histogram",
	} {
		if value := getenv(key); value != "" && !strings.EqualFold(value, allowed) {
			return nil, settingError(key)
		}
	}
	return settings, nil
}

// provider constructors also read these defaults before their explicit options.
// validate their syntax even though tnl owns the effective limits and selectors.
func validateSDKProviderEnvironment(getenv func(string) string) error {
	for _, key := range []string{
		"OTEL_GO_X_CARDINALITY_LIMIT", "OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT", "OTEL_ATTRIBUTE_COUNT_LIMIT",
		"OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT", "OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT", "OTEL_SPAN_EVENT_COUNT_LIMIT",
		"OTEL_EVENT_ATTRIBUTE_COUNT_LIMIT", "OTEL_SPAN_LINK_COUNT_LIMIT", "OTEL_LINK_ATTRIBUTE_COUNT_LIMIT",
	} {
		if value := getenv(key); value != "" {
			if _, err := strconv.Atoi(value); err != nil {
				return settingError(key)
			}
		}
	}
	for _, key := range []string{"OTEL_METRIC_EXPORT_INTERVAL", "OTEL_METRIC_EXPORT_TIMEOUT"} {
		if value := getenv(key); value != "" {
			if _, err := milliseconds(value, time.Second, 10*time.Minute); err != nil {
				return settingError(key)
			}
		}
	}
	switch getenv("OTEL_TRACES_SAMPLER") {
	case "", "always_on", "always_off", "parentbased_always_on", "parentbased_always_off":
	case "traceidratio", "parentbased_traceidratio":
		ratio, err := strconv.ParseFloat(getenv("OTEL_TRACES_SAMPLER_ARG"), 64)
		if err != nil || !(ratio >= 0 && ratio <= 1) {
			return settingError("OTEL_TRACES_SAMPLER_ARG")
		}
	default:
		return settingError("OTEL_TRACES_SAMPLER")
	}
	return nil
}

func validServiceName(value string) bool {
	switch value {
	case "", "tnl", "tnld", "tnl-accounts", "otel-collector":
		return true
	}
	return false
}

// zero fields mean unset, so precedence does not need to read or parse raw input.
type exporterSettings struct {
	endpoint    string
	headers     map[string]string
	timeout     time.Duration
	compression string
	roots       *x509.CertPool
	client      *tls.Certificate
}

func parseExporterSettings(getenv func(string) string, prefix string) (exporterSettings, error) {
	c := exporterSettings{endpoint: getenv(prefix + "ENDPOINT"), compression: getenv(prefix + "COMPRESSION")}
	if c.endpoint != "" {
		u, err := url.Parse(c.endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(c.endpoint, "#") {
			return c, settingError(prefix + "ENDPOINT")
		}
	}
	if protocol := getenv(prefix + "PROTOCOL"); protocol != "" && protocol != "http/protobuf" {
		return c, settingError(prefix + "PROTOCOL")
	}
	if insecure := getenv(prefix + "INSECURE"); insecure != "" && insecure != "false" {
		return c, settingError(prefix + "INSECURE")
	}
	var err error
	c.timeout, err = milliseconds(getenv(prefix+"TIMEOUT"), 0, 10*time.Second)
	if err != nil {
		return c, settingError(prefix + "TIMEOUT")
	}
	if raw := getenv(prefix + "HEADERS"); raw != "" {
		if len(raw) > 8192 {
			return c, settingError(prefix + "HEADERS")
		}
		c.headers = make(map[string]string)
		for _, pair := range strings.Split(raw, ",") {
			key, value, ok := strings.Cut(pair, "=")
			key = strings.TrimSpace(key)
			value, err = url.PathUnescape(strings.TrimSpace(value))
			if !ok || err != nil || !validHeaderName(key) || strings.ContainsAny(value, "\r\n\x00") {
				return c, settingError(prefix + "HEADERS")
			}
			c.headers[key] = value
		}
	}
	switch c.compression {
	case "", "none", "gzip":
	default:
		return c, settingError(prefix + "COMPRESSION")
	}
	if path := getenv(prefix + "CERTIFICATE"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return c, settingError(prefix + "CERTIFICATE")
		}
		c.roots = x509.NewCertPool()
		if !c.roots.AppendCertsFromPEM(pem) {
			return c, settingError(prefix + "CERTIFICATE")
		}
	}
	cert, key := getenv(prefix+"CLIENT_CERTIFICATE"), getenv(prefix+"CLIENT_KEY")
	if cert != "" || key != "" {
		certPEM, err := os.ReadFile(cert)
		if err != nil {
			return c, settingError(prefix + "CLIENT_CERTIFICATE")
		}
		keyPEM, err := os.ReadFile(key)
		if err != nil {
			return c, settingError(prefix + "CLIENT_KEY")
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return c, settingError(prefix + "CLIENT_CERTIFICATE")
		}
		c.client = &pair
	}
	return c, nil
}

func signalConfig(getenv func(string) string, signal string, generic, specific exporterSettings) (SignalConfig, error) {
	c := SignalConfig{Timeout: 5 * time.Second}
	switch getenv("OTEL_" + signal + "_EXPORTER") {
	case "none":
		return c, nil
	case "", "otlp":
	default:
		return c, settingError("OTEL_" + signal + "_EXPORTER")
	}
	c.Endpoint = specific.endpoint
	if c.Endpoint == "" && generic.endpoint != "" {
		c.Endpoint = strings.TrimRight(generic.endpoint, "/") + "/v1/" + strings.ToLower(signal)
	}
	if c.Endpoint == "" {
		return c, nil
	}
	c.Headers = generic.headers
	if specific.headers != nil {
		c.Headers = specific.headers
	}
	if generic.timeout != 0 {
		c.Timeout = generic.timeout
	}
	if specific.timeout != 0 {
		c.Timeout = specific.timeout
	}
	// the periodic reader and batch processor may shorten the exporter timeout.
	key := map[string]string{"METRICS": "OTEL_METRIC_EXPORT_TIMEOUT", "TRACES": "OTEL_BSP_EXPORT_TIMEOUT", "LOGS": "OTEL_BLRP_EXPORT_TIMEOUT"}[signal]
	if value := getenv(key); value != "" {
		d, err := milliseconds(value, c.Timeout, 10*time.Second)
		if err != nil {
			return c, settingError(key)
		}
		c.Timeout = min(c.Timeout, d)
	}
	c.Gzip = generic.compression == "gzip"
	if specific.compression != "" {
		c.Gzip = specific.compression == "gzip"
	}
	c.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: generic.roots}
	if specific.roots != nil {
		c.TLS.RootCAs = specific.roots
	}
	client := generic.client
	if specific.client != nil {
		client = specific.client
	}
	if client != nil {
		c.TLS.Certificates = []tls.Certificate{*client}
	}
	return c, nil
}

func validHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			continue
		}
		return false
	}
	return true
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
	if s.TLS != nil {
		transport.TLSClientConfig = s.TLS.Clone()
	}
	transport.MaxConnsPerHost = 2
	transport.MaxIdleConnsPerHost = 2
	transport.ResponseHeaderTimeout = s.Timeout
	return &http.Client{Timeout: s.Timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
