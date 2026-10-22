package discovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

const fixtureHost = "api.example.us-east-1.eks.amazonaws.com"

var fixtureCredentials = aws.Credentials{AccessKeyID: "fixture-key", SecretAccessKey: "fixture-secret", SessionToken: "fixture-session"}

func certificate(t *testing.T, hostname string, serial int64) (string, tls.Certificate) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, DNSNames: []string{hostname}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, root, root, public, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// sdkFixture uses the actual SDK serializers, HTTPS client, SigV4 signer and
// deserializers. recomputing Authorization also verifies the signed body/scope.
func sdkFixture(t *testing.T, handler http.HandlerFunc) AWS {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, (2<<20)+1))
		if err != nil {
			t.Error(err)
			return
		}
		service := "rds"
		if strings.HasPrefix(request.URL.Path, "/clusters/") {
			service = "eks"
		} else if bytes.Contains(body, []byte("Action=GetCallerIdentity")) {
			service = "sts"
		}
		stamp, err := time.Parse("20060102T150405Z", request.Header.Get("X-Amz-Date"))
		if err != nil {
			t.Errorf("unsigned request: %v", err)
			w.WriteHeader(403)
			return
		}
		auth := request.Header.Get("Authorization")
		copy := request.Clone(request.Context())
		copy.Header = request.Header.Clone()
		copy.Header.Del("Authorization")
		copy.URL.Scheme, copy.URL.Host = "https", request.Host
		// net/http can add Accept-Encoding after signing. only the SDK's
		// declared signed headers belong in the recomputed canonical request.
		parts := strings.Split(strings.Split(auth, "SignedHeaders=")[1], ",")
		signed := ";" + parts[0] + ";"
		for name := range copy.Header {
			if !strings.Contains(signed, ";"+strings.ToLower(name)+";") {
				copy.Header.Del(name)
			}
		}
		sum := sha256.Sum256(body)
		if err := v4.NewSigner().SignHTTP(request.Context(), fixtureCredentials, copy, hex.EncodeToString(sum[:]), service, "us-east-1", stamp); err != nil || copy.Header.Get("Authorization") != auth || request.Header.Get("X-Amz-Security-Token") != fixtureCredentials.SessionToken {
			t.Error("incorrect SigV4 signature, credential scope or session token")
			w.WriteHeader(403)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		if service == "sts" {
			w.Header().Set("Content-Type", "text/xml")
			io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:role/fixture</Arn><UserId>fixture</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
			return
		}
		handler(w, request)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	t.Cleanup(client.CloseIdleConnections)
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(fixtureCredentials.AccessKeyID, fixtureCredentials.SecretAccessKey, fixtureCredentials.SessionToken), HTTPClient: boundedHTTP{client}, RetryMaxAttempts: 1}
	clients := Clients{EKS: eks.NewFromConfig(cfg, func(o *eks.Options) { o.BaseEndpoint = aws.String(server.URL) }), RDS: rds.NewFromConfig(cfg, func(o *rds.Options) { o.BaseEndpoint = aws.String(server.URL) }), Caller: sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = aws.String(server.URL) })}
	return AWS{Load: func(context.Context, string) (Clients, error) { return clients, nil }}
}

func eksResponse(ca string) map[string]any {
	return map[string]any{"name": "demo", "arn": "arn:aws:eks:us-east-1:123456789012:cluster/demo", "createdAt": 1700000000.5, "status": "ACTIVE", "endpoint": "https://" + fixtureHost, "certificateAuthority": map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(ca))}, "accessConfig": map[string]any{"authenticationMode": "API"}}
}

func TestSDKHTTPSDescribeEKSVerifiedTLSAndMalformedMetadata(t *testing.T) {
	ca, cert := certificate(t, fixtureHost, 1)
	request := Request{Type: "eks", Region: "us-east-1", Cluster: "demo", Protocol: "kubernetes"}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		kind   Kind
	}{
		{name: "valid"},
		{name: "wrong-selector", mutate: func(c map[string]any) { c["name"] = "other" }, kind: Metadata},
		{name: "wrong-account", mutate: func(c map[string]any) { c["arn"] = "arn:aws:eks:us-east-1:999999999999:cluster/demo" }, kind: Metadata},
		{name: "wrong-region", mutate: func(c map[string]any) { c["arn"] = "arn:aws:eks:us-west-2:123456789012:cluster/demo" }, kind: Metadata},
		{name: "wrong-resource", mutate: func(c map[string]any) { c["arn"] = "arn:aws:eks:us-east-1:123456789012:cluster/other" }, kind: Metadata},
		{name: "creating", mutate: func(c map[string]any) { c["status"] = "CREATING" }, kind: NotReady},
		{name: "http", mutate: func(c map[string]any) { c["endpoint"] = "http://" + fixtureHost }, kind: Metadata},
		{name: "userinfo", mutate: func(c map[string]any) { c["endpoint"] = "https://secret:password@" + fixtureHost }, kind: Metadata},
		{name: "path", mutate: func(c map[string]any) { c["endpoint"] = "https://" + fixtureHost + "/private" }, kind: Metadata},
		{name: "ip", mutate: func(c map[string]any) { c["endpoint"] = "https://127.0.0.1" }, kind: Metadata},
		{name: "malformed-base64", mutate: func(c map[string]any) { c["certificateAuthority"] = map[string]any{"data": "?"} }, kind: Metadata},
		{name: "oversized-ca", mutate: func(c map[string]any) {
			c["certificateAuthority"] = map[string]any{"data": strings.Repeat("A", 100000)}
		}, kind: Metadata},
		{name: "private-key", mutate: func(c map[string]any) {
			c["certificateAuthority"] = map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(ca + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))}
		}, kind: Metadata},
		{name: "missing-creation", mutate: func(c map[string]any) { delete(c, "createdAt") }, kind: Metadata},
		{name: "unknown-auth", mutate: func(c map[string]any) { c["accessConfig"] = map[string]any{"authenticationMode": "unknown"} }, kind: Metadata},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := eksResponse(ca)
			if tc.mutate != nil {
				tc.mutate(body)
			}
			provider := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/clusters/demo" {
					t.Error("not an exact EKS selector")
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"cluster": body})
			})
			target, err := provider.Discover(t.Context(), request)
			if tc.kind != "" {
				if err == nil || ErrorKind(err) != tc.kind {
					t.Fatalf("kind = %v, %v", ErrorKind(err), err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if target.Address != fixtureHost+":443" || target.CA != ca || target.ResourceID != "2023-11-14T22:13:20.5Z" {
				t.Fatalf("incorrect target metadata: %v", target)
			}
			verifier, err := target.Verifier()
			if err != nil {
				t.Fatal(err)
			}
			expectedRoots := x509.NewCertPool()
			expectedRoots.AppendCertsFromPEM([]byte(ca))
			if verifier.InsecureSkipVerify || verifier.ServerName != fixtureHost || !verifier.RootCAs.Equal(expectedRoots) {
				t.Fatal("target TLS trust was not exact")
			}
			front, back := net.Pipe()
			defer front.Close()
			defer back.Close()
			done := make(chan error, 1)
			go func() {
				server := tls.Server(back, &tls.Config{Certificates: []tls.Certificate{cert}})
				done <- server.HandshakeContext(t.Context())
			}()
			if _, err := (targettransport.Transport{Protocol: config.ProtocolName("kubernetes"), TLS: verifier}).Handshake(t.Context(), front); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func rdsXML(cluster bool, engine, endpoint, port, id, status, account string) string {
	if cluster {
		return fmt.Sprintf(`<DescribeDBClustersResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/"><DescribeDBClustersResult><DBClusters><DBCluster><DBClusterIdentifier>demo</DBClusterIdentifier><DBClusterArn>arn:aws:rds:us-east-1:%s:cluster:demo</DBClusterArn><DbClusterResourceId>%s</DbClusterResourceId><Engine>%s</Engine><Status>%s</Status><Endpoint>%s</Endpoint><ReaderEndpoint>demo-ro.cluster-abc.us-east-1.rds.amazonaws.com</ReaderEndpoint><Port>%s</Port></DBCluster></DBClusters></DescribeDBClustersResult></DescribeDBClustersResponse>`, account, id, engine, status, endpoint, port)
	}
	return fmt.Sprintf(`<DescribeDBInstancesResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/"><DescribeDBInstancesResult><DBInstances><DBInstance><DBInstanceIdentifier>demo</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:%s:db:demo</DBInstanceArn><DbiResourceId>%s</DbiResourceId><Engine>%s</Engine><DBInstanceStatus>%s</DBInstanceStatus><CACertificateIdentifier>rds-ca-rsa2048-g1</CACertificateIdentifier><Endpoint><Address>%s</Address><Port>%s</Port></Endpoint></DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`, account, id, engine, status, endpoint, port)
}

func TestSDKHTTPSRDSExactSelectorsEnginesAndReaderEndpoint(t *testing.T) {
	for _, cluster := range []bool{false, true} {
		for _, engine := range []string{"postgres", "aurora-postgresql", "mysql", "aurora-mysql", "docdb", "neptune", "oracle-ee"} {
			for _, protocol := range []string{"postgres", "mysql"} {
				t.Run(fmt.Sprintf("cluster=%v/%s/%s", cluster, engine, protocol), func(t *testing.T) {
					provider := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
						if err := r.ParseForm(); err != nil {
							t.Error(err)
						}
						action, selector := "DescribeDBInstances", "DBInstanceIdentifier"
						if cluster {
							action, selector = "DescribeDBClusters", "DBClusterIdentifier"
						}
						if r.Form.Get("Action") != action || r.Form.Get(selector) != "demo" || r.Form.Get("Marker") != "" {
							t.Error("RDS enumeration or wrong exact selector")
						}
						w.Header().Set("Content-Type", "text/xml")
						io.WriteString(w, rdsXML(cluster, engine, "demo.abc.us-east-1.rds.amazonaws.com", "5432", "db-immutable", "available", "123456789012"))
					})
					request := Request{Type: "rds", Region: "us-east-1", Instance: "demo", Protocol: protocol}
					if cluster {
						request.Instance, request.Cluster, request.Endpoint = "", "demo", "reader"
					}
					target, err := provider.Discover(t.Context(), request)
					allowed := protocol == "postgres" && (engine == "postgres" || engine == "aurora-postgresql") || protocol == "mysql" && (engine == "mysql" || engine == "aurora-mysql")
					if !allowed {
						if err == nil || ErrorKind(err) != Metadata {
							t.Fatalf("incompatible engine admitted: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if cluster && target.ServerName != "demo-ro.cluster-abc.us-east-1.rds.amazonaws.com" || !cluster && target.ServerName != "demo.abc.us-east-1.rds.amazonaws.com" {
						t.Fatal("wrong endpoint selected")
					}
					verifier, err := target.Verifier()
					if err != nil || verifier == nil || verifier.RootCAs == nil || verifier.InsecureSkipVerify {
						t.Fatal("RDS target trust missing", err)
					}
				})
			}
		}
	}
}

func TestSDKHTTPSFailuresAreSafeClassifiedAndBounded(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
		kind   Kind
	}{
		{"AccessDeniedException", 403, Permission}, {"ResourceNotFoundException", 404, NotFound}, {"ExpiredTokenException", 403, Authentication}, {"ThrottlingException", 429, Unavailable}, {"ServiceUnavailableException", 503, Unavailable},
	} {
		t.Run(tc.code, func(t *testing.T) {
			provider := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Amzn-Errortype", tc.code)
				w.WriteHeader(tc.status)
				io.WriteString(w, `{"message":"secret password https://user:pass@private.invalid"}`)
			})
			_, err := provider.Discover(t.Context(), Request{Type: "eks", Region: "us-east-1", Cluster: "demo", Protocol: "kubernetes"})
			if err == nil || ErrorKind(err) != tc.kind {
				t.Fatalf("classification: %v", err)
			}
			var api smithy.APIError
			if !errors.As(err, &api) || api.ErrorCode() != tc.code {
				t.Fatal("SDK cause lost")
			}
			for _, text := range []string{err.Error(), fmt.Sprintf("%#v", err), failure.SafeMessage(err, failure.Unexpected)} {
				if strings.Contains(text, "secret") || strings.Contains(text, "user:pass") {
					t.Fatal("provider data leaked")
				}
			}
		})
	}
	for _, huge := range []bool{false, true} {
		t.Run(fmt.Sprint("timeout-or-bounds/", huge), func(t *testing.T) {
			var calls atomic.Int32
			provider := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if huge {
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, strings.Repeat("A", (1<<20)+1))
					return
				}
				<-r.Context().Done()
			})
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			_, err := provider.Discover(ctx, Request{Type: "eks", Region: "us-east-1", Cluster: "demo", Protocol: "kubernetes"})
			if huge {
				if err == nil {
					t.Fatal("oversized metadata accepted")
				}
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline lost: %v", err)
			}
			if calls.Load() > 1 {
				t.Fatal("unexpected SDK retry")
			}
		})
	}
}

func TestSDKRefreshDetectsCreationAndCARotationAcrossPreparations(t *testing.T) {
	for _, field := range []string{"createdAt", "certificateAuthority"} {
		t.Run(field, func(t *testing.T) {
			original, _ := certificate(t, fixtureHost, 1)
			rotated, _ := certificate(t, fixtureHost, 2)
			var changed atomic.Bool
			provider := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				body := eksResponse(original)
				if changed.Load() {
					if field == "createdAt" {
						body[field] = 1700000001.5
					} else {
						body[field] = map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(rotated))}
					}
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"cluster": body})
			})
			resolver, advance := resolverFixture(t, provider, Options{TTL: time.Second})
			old, err := resolver.Prepare(t.Context(), requestFixture())
			if err != nil {
				t.Fatal(err)
			}
			changed.Store(true)
			advance(time.Second)
			if _, _, err := old.ResolveTarget(t.Context()); err == nil || ErrorKind(err) != Changed {
				t.Fatal("real SDK refresh reused replaced resource/trust", err)
			}
			fresh, err := resolver.Prepare(t.Context(), requestFixture())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := fresh.ResolveTarget(t.Context()); err != nil {
				t.Fatal("new preparation rejected current SDK metadata", err)
			}
		})
	}
}

func TestSDKRDSMalformedMetadataAndProviderErrorsFailClosed(t *testing.T) {
	for _, cluster := range []bool{false, true} {
		valid := rdsXML(cluster, "postgres", "demo.abc.us-east-1.rds.amazonaws.com", "5432", "db-immutable", "available", "123456789012")
		for _, tc := range []struct {
			name, from, to string
			kind           Kind
		}{
			{"port-zero", "<Port>5432</Port>", "<Port>0</Port>", Metadata},
			{"port-overflow", "<Port>5432</Port>", "<Port>65536</Port>", Metadata},
			{"wrong-account", "123456789012", "999999999999", Metadata},
			{"wrong-selector", "<DBInstanceIdentifier>demo</DBInstanceIdentifier>", "<DBInstanceIdentifier>other</DBInstanceIdentifier>", Metadata},
			{"wrong-cluster-selector", "<DBClusterIdentifier>demo</DBClusterIdentifier>", "<DBClusterIdentifier>other</DBClusterIdentifier>", Metadata},
			{"missing-resource-id", "db-immutable", "", Metadata},
			{"ip-endpoint", "demo.abc.us-east-1.rds.amazonaws.com", "127.0.0.1", Metadata},
			{"endpoint-userinfo", "demo.abc.us-east-1.rds.amazonaws.com", "user:password@private.invalid", Metadata},
			{"not-ready", "<Status>available</Status>", "<Status>creating</Status>", NotReady},
			{"instance-not-ready", "<DBInstanceStatus>available</DBInstanceStatus>", "<DBInstanceStatus>creating</DBInstanceStatus>", NotReady},
		} {
			if !strings.Contains(valid, tc.from) {
				continue
			}
			t.Run(fmt.Sprintf("cluster=%v/%s", cluster, tc.name), func(t *testing.T) {
				provider := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/xml")
					io.WriteString(w, strings.ReplaceAll(valid, tc.from, tc.to))
				})
				request := Request{Type: "rds", Region: "us-east-1", Instance: "demo", Protocol: "postgres"}
				if cluster {
					request.Instance, request.Cluster = "", "demo"
				}
				if _, err := provider.Discover(t.Context(), request); err == nil || ErrorKind(err) != tc.kind {
					t.Fatal("malformed RDS metadata accepted", err)
				}
			})
		}
	}
	for _, code := range []string{"DBInstanceNotFound", "DBClusterNotFoundFault", "AccessDenied", "Throttling"} {
		t.Run(code, func(t *testing.T) {
			provider := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/xml")
				w.WriteHeader(400)
				fmt.Fprintf(w, `<ErrorResponse><Error><Code>%s</Code><Message>secret password</Message></Error></ErrorResponse>`, code)
			})
			_, err := provider.Discover(t.Context(), Request{Type: "rds", Region: "us-east-1", Instance: "demo", Protocol: "postgres"})
			expected := NotFound
			if code == "AccessDenied" {
				expected = Permission
			}
			if code == "Throttling" {
				expected = Unavailable
			}
			if err == nil || ErrorKind(err) != expected || strings.Contains(err.Error(), "secret") {
				t.Fatal("RDS error was not safely classified", err)
			}
		})
	}
}

func TestLoadUsesTaskCredentialChainAndIgnoresAWSServiceEndpointOverrides(t *testing.T) {
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "no-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "no-credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		if r.Header.Get("Authorization") != "fixture-task-authorization" {
			t.Error("task credential authorization was not passed")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"AccessKeyId": fixtureCredentials.AccessKeyID, "SecretAccessKey": fixtureCredentials.SecretAccessKey, "Token": fixtureCredentials.SessionToken, "Expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	}))
	defer server.Close()
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL)
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "fixture-task-authorization")
	for _, key := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_EKS", "AWS_ENDPOINT_URL_RDS", "AWS_ENDPOINT_URL_STS"} {
		t.Setenv(key, "https://untrusted.invalid")
	}
	clients, err := Load(t.Context(), "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 {
		t.Fatal("normal task-role credential provider not used")
	}
	eksOptions, rdsOptions, stsOptions := clients.EKS.(*eks.Client).Options(), clients.RDS.(*rds.Client).Options(), clients.Caller.(*sts.Client).Options()
	if eksOptions.Region != "us-east-1" || rdsOptions.Region != "us-east-1" || stsOptions.Region != "us-east-1" || eksOptions.BaseEndpoint != nil || rdsOptions.BaseEndpoint != nil || stsOptions.BaseEndpoint != nil {
		t.Fatal("explicit region or AWS endpoint boundary was not retained")
	}
	credential, err := eksOptions.Credentials.Retrieve(t.Context())
	if err != nil || credential.AccessKeyID != fixtureCredentials.AccessKeyID || credential.SessionToken != fixtureCredentials.SessionToken {
		t.Fatal("task credentials missing from SDK client", err)
	}
}
