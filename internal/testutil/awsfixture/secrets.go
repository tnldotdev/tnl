// package awsfixture implements the bounded Secrets Manager and STS HTTPS wire
// protocols used by publisher bootstrap. it never uses ambient AWS credentials.
package awsfixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const Account = "123456789012"
const Region = "us-east-1"
const credentialID = "AKIDLOCALFIXTURE"
const credentialSecret = "local-fixture-signing-key"

type Secret struct {
	Name     string
	ARN      string
	Tags     []map[string]string
	Versions map[string]string
	Stages   map[string][]string
}

type Call struct{ Operation, SecretID, Token string }

type Fixture struct {
	mu      sync.Mutex
	t       *testing.T
	Server  *httptest.Server
	secrets map[string]*Secret
	calls   []Call
	lose    string
	deny    string
	account string
	block   string
	started chan struct{}
}

func New(t *testing.T) *Fixture {
	f := &Fixture{t: t, secrets: map[string]*Secret{}, account: Account}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

func (f *Fixture) Clients() (*secretsmanager.Client, *sts.Client) {
	cfg := aws.Config{Region: Region, Credentials: credentials.NewStaticCredentialsProvider(credentialID, credentialSecret, ""), HTTPClient: f.Server.Client(), RetryMaxAttempts: 1}
	return secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) { o.BaseEndpoint = aws.String(f.Server.URL) }), sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = aws.String(f.Server.URL) })
}

func (f *Fixture) LoseReply(operation string) { f.mu.Lock(); defer f.mu.Unlock(); f.lose = operation }
func (f *Fixture) BlockOnce(operation string) <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block, f.started = operation, make(chan struct{})
	return f.started
}
func (f *Fixture) Deny(code string)     { f.mu.Lock(); defer f.mu.Unlock(); f.deny = code }
func (f *Fixture) Account(value string) { f.mu.Lock(); defer f.mu.Unlock(); f.account = value }
func (f *Fixture) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}
func (f *Fixture) Add(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &Secret{Name: name, ARN: "arn:aws:secretsmanager:" + Region + ":" + Account + ":secret:" + name + "-AbCdEf", Versions: map[string]string{}, Stages: map[string][]string{}}
	f.secrets[s.ARN] = s
	return s.ARN
}
func (f *Fixture) Alter(arn string, change func(*Secret)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f.secrets[arn])
}
func (f *Fixture) Value(arn, version string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.secrets[arn].Versions[version]
}

func (f *Fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(body) > 16384 || r.Method != "POST" || r.TLS == nil {
		f.t.Error("unbounded or non-HTTPS AWS request")
		w.WriteHeader(400)
		return
	}
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "secretsmanager.")
	service := "secretsmanager"
	if op == "" {
		service = "sts"
		op = "GetCallerIdentity"
	}
	// recompute SigV4 over the actual received body and headers, rather than
	// accepting a request merely because it has an Authorization header.
	clone := r.Clone(context.Background())
	clone.URL.Scheme = "https"
	clone.URL.Host = r.Host
	authorization := clone.Header.Get("Authorization")
	_, signed, _ := strings.Cut(authorization, "SignedHeaders=")
	signed, _, _ = strings.Cut(signed, ",")
	for header := range clone.Header {
		if !strings.Contains(";"+signed+";", ";"+strings.ToLower(header)+";") {
			clone.Header.Del(header)
		}
	}
	when, err := time.Parse("20060102T150405Z", clone.Header.Get("X-Amz-Date"))
	digest := sha256.Sum256(body)
	if err != nil {
		f.t.Error("missing AWS signing date")
		w.WriteHeader(403)
		return
	}
	err = v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: credentialID, SecretAccessKey: credentialSecret}, clone, hex.EncodeToString(digest[:]), service, Region, when)
	if err != nil || authorization == "" || clone.Header.Get("Authorization") != authorization {
		f.t.Error("invalid AWS SigV4 signature")
		w.WriteHeader(403)
		return
	}
	if f.deny != "" {
		f.problem(w, f.deny)
		return
	}
	if service == "sts" {
		f.calls = append(f.calls, Call{Operation: op})
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::%s:user/fixture</Arn><UserId>fixture</UserId><Account>%s</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>fixture</RequestId></ResponseMetadata></GetCallerIdentityResponse>`, f.account, f.account)
		return
	}
	var input struct {
		Name, SecretId, ClientRequestToken, VersionId, SecretString, KmsKeyId string
		Tags                                                                  []map[string]string
		VersionStages                                                         []string
	}
	if json.Unmarshal(body, &input) != nil {
		w.WriteHeader(400)
		return
	}
	f.calls = append(f.calls, Call{Operation: op, SecretID: input.SecretId, Token: input.ClientRequestToken})
	if len(f.calls) > 200 {
		f.t.Error("unbounded AWS calls")
		w.WriteHeader(500)
		return
	}
	if f.block == op {
		f.block = ""
		close(f.started)
		<-r.Context().Done()
		return
	}
	var secret *Secret
	for _, s := range f.secrets {
		if s.ARN == input.SecretId || s.Name == input.SecretId || op == "CreateSecret" && s.Name == input.Name {
			secret = s
		}
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	var output any
	switch op {
	case "CreateSecret":
		if secret != nil {
			f.problem(w, "ResourceExistsException")
			return
		}
		secret = &Secret{Name: input.Name, ARN: "arn:aws:secretsmanager:" + Region + ":" + Account + ":secret:" + input.Name + "-AbCdEf", Tags: input.Tags, Versions: map[string]string{input.ClientRequestToken: input.SecretString}, Stages: map[string][]string{input.ClientRequestToken: {"AWSCURRENT"}}}
		f.secrets[secret.ARN] = secret
		output = map[string]any{"ARN": secret.ARN, "Name": secret.Name, "VersionId": input.ClientRequestToken}
	case "DescribeSecret":
		if secret == nil {
			f.problem(w, "ResourceNotFoundException")
			return
		}
		output = map[string]any{"ARN": secret.ARN, "Name": secret.Name, "Tags": secret.Tags, "VersionIdsToStages": secret.Stages}
	case "GetSecretValue":
		if input.VersionId == "" {
			f.t.Error("unpinned secret read")
			w.WriteHeader(400)
			return
		}
		if secret == nil {
			f.problem(w, "ResourceNotFoundException")
			return
		}
		value, found := secret.Versions[input.VersionId]
		if !found {
			f.problem(w, "ResourceNotFoundException")
			return
		}
		output = map[string]any{"ARN": secret.ARN, "Name": secret.Name, "VersionId": input.VersionId, "SecretString": value}
	case "PutSecretValue":
		if secret == nil {
			f.problem(w, "ResourceNotFoundException")
			return
		}
		if previous, ok := secret.Versions[input.ClientRequestToken]; ok && previous != input.SecretString {
			f.problem(w, "ResourceExistsException")
			return
		}
		if len(input.VersionStages) != 1 || input.VersionStages[0] != "tnl-"+input.ClientRequestToken {
			f.t.Error("identity write changed default version stage")
			w.WriteHeader(400)
			return
		}
		secret.Versions[input.ClientRequestToken] = input.SecretString
		secret.Stages[input.ClientRequestToken] = input.VersionStages
		output = map[string]any{"ARN": secret.ARN, "Name": secret.Name, "VersionId": input.ClientRequestToken}
	default:
		f.t.Errorf("unexpected AWS operation %q", op)
		w.WriteHeader(400)
		return
	}
	if f.lose == op {
		f.lose = ""
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			f.t.Error(err)
			return
		}
		_ = conn.Close()
		return
	}
	_ = json.NewEncoder(w).Encode(output)
}

func (f *Fixture) problem(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(400)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "Message": "fixture-private-provider-body"})
}
