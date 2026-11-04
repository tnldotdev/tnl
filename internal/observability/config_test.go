package observability

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestExporterRawSettingsReportTheirSource(t *testing.T) {
	ca, cert, key := exporterTLSFiles(t)
	invalidPEM := filepath.Join(t.TempDir(), "secret-invalid.pem")
	if err := os.WriteFile(invalidPEM, []byte("secret-invalid-pem"), 0600); err != nil {
		t.Fatal(err)
	}
	valid := map[string]string{
		"ENDPOINT": "https://collector.invalid/base", "PROTOCOL": "http/protobuf", "INSECURE": "false",
		"TIMEOUT": "100", "HEADERS": "Authorization=Bearer%20valid", "COMPRESSION": "gzip",
		"CERTIFICATE": ca, "CLIENT_CERTIFICATE": cert, "CLIENT_KEY": key,
	}
	for _, spec := range []struct{ name, suffix, value string }{
		{"endpoint scheme", "ENDPOINT", "http://secret.invalid"},
		{"endpoint syntax", "ENDPOINT", "https://secret%zz.invalid"},
		{"endpoint credentials", "ENDPOINT", "https://user:secret@collector.invalid"},
		{"endpoint query", "ENDPOINT", "https://collector.invalid?secret=value"},
		{"endpoint empty query", "ENDPOINT", "https://collector.invalid?"},
		{"endpoint fragment", "ENDPOINT", "https://collector.invalid#secret"},
		{"endpoint empty fragment", "ENDPOINT", "https://collector.invalid#"},
		{"protocol", "PROTOCOL", "secret-grpc"},
		{"insecure", "INSECURE", "secret-true"},
		{"timeout syntax", "TIMEOUT", "secret-timeout"},
		{"timeout zero", "TIMEOUT", "0"},
		{"timeout limit", "TIMEOUT", "10001"},
		{"header name", "HEADERS", "invalid@name=secret"},
		{"header encoding", "HEADERS", "Authorization=secret%zz"},
		{"header newline", "HEADERS", "Authorization=secret%0d%0aevil"},
		{"header size", "HEADERS", "Authorization=" + strings.Repeat("secret", 1400)},
		{"compression", "COMPRESSION", "secret-compression"},
		{"ca file", "CERTIFICATE", "/missing/secret-ca.pem"},
		{"ca pem", "CERTIFICATE", invalidPEM},
		{"client certificate file", "CLIENT_CERTIFICATE", "/missing/secret-client.pem"},
		{"client certificate pem", "CLIENT_CERTIFICATE", invalidPEM},
		{"client certificate missing", "CLIENT_CERTIFICATE", ""},
		{"client key file", "CLIENT_KEY", "/missing/secret-key.pem"},
		{"client key missing", "CLIENT_KEY", ""},
	} {
		for _, scope := range []string{"", "METRICS_", "TRACES_", "LOGS_"} {
			prefix := "OTEL_EXPORTER_OTLP_" + scope
			for _, mode := range []string{"no endpoint", "overridden", "exporters disabled", "sdk disabled"} {
				t.Run(prefix+spec.name+"/"+mode, func(t *testing.T) {
					values := make(map[string]string)
					for _, p := range []string{"OTEL_EXPORTER_OTLP_", "OTEL_EXPORTER_OTLP_METRICS_", "OTEL_EXPORTER_OTLP_TRACES_", "OTEL_EXPORTER_OTLP_LOGS_"} {
						for suffix, value := range valid {
							if suffix != "ENDPOINT" || mode != "no endpoint" {
								values[p+suffix] = value
							}
						}
					}
					if mode == "exporters disabled" {
						for _, signal := range []string{"METRICS", "TRACES", "LOGS"} {
							values["OTEL_"+signal+"_EXPORTER"] = "none"
						}
					}
					if mode == "sdk disabled" {
						values["OTEL_SDK_DISABLED"] = "TrUe"
					}
					values[prefix+spec.suffix] = spec.value
					config, err := ConfigFromEnv(func(k string) string { return values[k] })
					if mode == "sdk disabled" {
						if err != nil || !config.Disabled || config.Metrics.Endpoint != "" || config.Traces.Endpoint != "" || config.Logs.Endpoint != "" {
							t.Fatal("disabled SDK parsed exporter settings", err)
						}
						return
					}
					assertExporterSettingError(t, err, prefix+spec.suffix)
				})
			}
		}
	}
}

func TestExporterEffectiveSettings(t *testing.T) {
	ca, cert, key := exporterTLSFiles(t)
	overrideCA, overrideCert, overrideKey := exporterTLSFiles(t)
	for _, signal := range []string{"METRICS", "TRACES", "LOGS"} {
		prefix := "OTEL_EXPORTER_OTLP_" + signal + "_"
		processorTimeout := map[string]string{"METRICS": "OTEL_METRIC_EXPORT_TIMEOUT", "TRACES": "OTEL_BSP_EXPORT_TIMEOUT", "LOGS": "OTEL_BLRP_EXPORT_TIMEOUT"}[signal]
		base := map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.invalid/base///", "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
			"OTEL_EXPORTER_OTLP_INSECURE": "false", "OTEL_EXPORTER_OTLP_TIMEOUT": "8000",
			"OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer%20secret,x-generic=secret", "OTEL_EXPORTER_OTLP_COMPRESSION": "gzip",
			"OTEL_EXPORTER_OTLP_CERTIFICATE": ca, "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE": cert, "OTEL_EXPORTER_OTLP_CLIENT_KEY": key,
		}
		for _, spec := range []struct {
			name, endpoint, header, ca, cert string
			values                           map[string]string
			timeout                          time.Duration
			gzip                             bool
		}{
			{"generic", "https://collector.invalid/base/v1/" + strings.ToLower(signal), "Authorization", ca, cert, nil, 8 * time.Second, true},
			{"signal overrides", "https://signal.invalid/exact/", "x-signal", overrideCA, overrideCert, map[string]string{
				prefix + "ENDPOINT": "https://signal.invalid/exact/", prefix + "HEADERS": "x-signal=secret", prefix + "TIMEOUT": "2000", prefix + "COMPRESSION": "none",
				prefix + "CERTIFICATE": overrideCA, prefix + "CLIENT_CERTIFICATE": overrideCert, prefix + "CLIENT_KEY": overrideKey,
			}, 2 * time.Second, false},
			{"exact origin", "https://signal.invalid", "Authorization", ca, cert, map[string]string{prefix + "ENDPOINT": "https://signal.invalid"}, 8 * time.Second, true},
			{"processor shortens timeout", "https://collector.invalid/base/v1/" + strings.ToLower(signal), "Authorization", ca, cert, map[string]string{prefix + "TIMEOUT": "2000", processorTimeout: "1000"}, time.Second, true},
			{"processor cannot lengthen timeout", "https://collector.invalid/base/v1/" + strings.ToLower(signal), "Authorization", ca, cert, map[string]string{prefix + "TIMEOUT": "2000", processorTimeout: "3000"}, 2 * time.Second, true},
			{"root override retains client pair", "https://collector.invalid/base/v1/" + strings.ToLower(signal), "Authorization", overrideCA, cert, map[string]string{prefix + "CERTIFICATE": overrideCA}, 8 * time.Second, true},
			{"client override retains roots", "https://collector.invalid/base/v1/" + strings.ToLower(signal), "Authorization", ca, overrideCert, map[string]string{prefix + "CLIENT_CERTIFICATE": overrideCert, prefix + "CLIENT_KEY": overrideKey}, 8 * time.Second, true},
		} {
			t.Run(signal+"/"+spec.name, func(t *testing.T) {
				values := maps.Clone(base)
				maps.Copy(values, spec.values)
				config, err := ConfigFromEnv(func(k string) string { return values[k] })
				if err != nil {
					t.Fatal(err)
				}
				got := map[string]SignalConfig{"METRICS": config.Metrics, "TRACES": config.Traces, "LOGS": config.Logs}[signal]
				if got.Endpoint != spec.endpoint || got.Timeout != spec.timeout || got.Gzip != spec.gzip || got.Headers[spec.header] == "" {
					t.Fatal("incorrect effective endpoint, timeout, compression, or headers")
				}
				if spec.header == "x-signal" && len(got.Headers) != 1 {
					t.Fatal("signal headers did not replace generic headers")
				}
				if spec.header == "Authorization" && got.Headers[spec.header] != "Bearer secret" {
					t.Fatal("header value was not percent-decoded")
				}
				caPEM, err := os.ReadFile(spec.ca)
				if err != nil {
					t.Fatal(err)
				}
				roots := x509.NewCertPool()
				if !roots.AppendCertsFromPEM(caPEM) || got.TLS == nil || !roots.Equal(got.TLS.RootCAs) || got.TLS.MinVersion != tls.VersionTLS12 {
					t.Fatal("incorrect receiver trust")
				}
				certPEM, err := os.ReadFile(spec.cert)
				if err != nil {
					t.Fatal(err)
				}
				block, _ := pem.Decode(certPEM)
				if len(got.TLS.Certificates) != 1 || !bytes.Equal(got.TLS.Certificates[0].Certificate[0], block.Bytes) {
					t.Fatal("incorrect client certificate")
				}
			})
		}
	}
}

func TestExporterRequiresAnEnabledExplicitEndpoint(t *testing.T) {
	for _, spec := range []struct {
		name   string
		values map[string]string
	}{
		{"unset", nil},
		{"settings without endpoints", map[string]string{"OTEL_EXPORTER_OTLP_HEADERS": "Authorization=secret", "OTEL_EXPORTER_OTLP_TIMEOUT": "1000", "OTEL_EXPORTER_OTLP_COMPRESSION": "gzip"}},
		{"otlp without endpoints", map[string]string{"OTEL_METRICS_EXPORTER": "otlp", "OTEL_TRACES_EXPORTER": "otlp", "OTEL_LOGS_EXPORTER": "otlp"}},
		{"none with endpoints", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.invalid", "OTEL_METRICS_EXPORTER": "none", "OTEL_TRACES_EXPORTER": "none", "OTEL_LOGS_EXPORTER": "none"}},
	} {
		t.Run(spec.name, func(t *testing.T) {
			config, err := ConfigFromEnv(func(k string) string { return spec.values[k] })
			if err != nil {
				t.Fatal(err)
			}
			for _, got := range []SignalConfig{config.Metrics, config.Traces, config.Logs} {
				if got.Endpoint != "" || got.Timeout != 5*time.Second || got.TLS != nil || got.Headers != nil || got.Gzip {
					t.Fatal("unconfigured or disabled signal acquired export settings")
				}
			}
		})
	}
}

func TestExporterSignalEndpointDoesNotEnableOtherSignals(t *testing.T) {
	for _, signal := range []string{"METRICS", "TRACES", "LOGS"} {
		t.Run(signal, func(t *testing.T) {
			key := "OTEL_EXPORTER_OTLP_" + signal + "_ENDPOINT"
			config, err := ConfigFromEnv(func(k string) string {
				if k == key {
					return "https://collector.invalid/exact"
				}
				return ""
			})
			if err != nil {
				t.Fatal(err)
			}
			for name, got := range map[string]SignalConfig{"METRICS": config.Metrics, "TRACES": config.Traces, "LOGS": config.Logs} {
				if name != signal {
					if got.Endpoint != "" {
						t.Fatal("unconfigured signal acquired an endpoint")
					}
					continue
				}
				if got.Endpoint != "https://collector.invalid/exact" || got.Timeout != 5*time.Second || got.Gzip || len(got.Headers) != 0 || got.TLS == nil || got.TLS.MinVersion != tls.VersionTLS12 || got.TLS.RootCAs != nil || len(got.TLS.Certificates) != 0 {
					t.Fatal("incorrect signal defaults")
				}
			}
		})
	}
}

func assertExporterSettingError(t *testing.T, err error, key string) {
	t.Helper()
	typed, ok := failure.Of(err)
	if !ok || typed.Setting() != failure.Setting(key) || typed.Reason() != failure.ObservabilityConfigInvalid {
		t.Fatalf("incorrect setting classification for %s: %v", key, err)
	}
	_, definition, ok := failure.Describe(err)
	if !ok || definition.Class != failure.Invalid || definition.Retry != failure.RetryAfterChange {
		t.Fatal("configuration error classification or retry policy changed")
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if strings.Contains(fmt.Sprintf("%v %+v %#v", cause, cause, cause), "secret") {
			t.Fatal("setting error retained an input value")
		}
	}
}

func exporterTLSFiles(t *testing.T) (caPath, certPath, keyPath string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath, certPath, keyPath = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "key.pem")
	for path, data := range map[string][]byte{
		caPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return caPath, certPath, keyPath
}
