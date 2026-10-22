package kubeconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var helperProfile = flag.String("tnl-kube-credential-profile", "", "private fixture exec profile")
var credentialOutputBytes = flag.Int("tnl-kube-output-bytes", 0, "fixture credential output size")

func TestCredentialOutputProcess(t *testing.T) {
	if *credentialOutputBytes == 0 {
		return
	}
	data := []byte(`{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1","status":{"token":"bounded-token"}}`)
	data = append(data, bytes.Repeat([]byte{' '}, *credentialOutputBytes-len(data))...)
	_, _ = os.Stdout.Write(data)
	os.Exit(0)
}

func TestCredentialOutputBoundThroughCopyAndSubprocess(t *testing.T) {
	const limit = 1 << 20
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{limit, limit + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{'k'}, size)
			var output limitedOutput
			_, err := io.Copy(&output, struct{ io.Reader }{bytes.NewReader(data)})
			if (err == nil) != (size == limit) || output.buffer.Len() > limit {
				t.Fatalf("copy captured %d bytes, error %v", output.buffer.Len(), err)
			}
			if size == limit && !bytes.Equal(output.buffer.Bytes(), data) {
				t.Fatal("copy changed exact-bound output")
			}
			token, err := execToken(t.Context(), binary, []string{"-test.run=^TestCredentialOutputProcess$", "-tnl-kube-output-bytes=" + strconv.Itoa(size)}, nil, "")
			if size == limit && (err != nil || token.Value != "bounded-token") || size > limit && (err != ErrCredential || token.Value != "") {
				t.Fatalf("credential subprocess error = %v", err)
			}
		})
	}
}

// this is an actual noninteractive exec plugin subprocess for client-go, not a
// mocked token callback. stdout must be exactly the exec credential wire shape.
func TestCredentialExecHelper(t *testing.T) {
	if *helperProfile == "" {
		return
	}
	profile, err := ReadProfile(*helperProfile)
	if err != nil {
		os.Exit(2)
	}
	credential, err := Credential(context.Background(), profile, nil)
	if err != nil {
		os.Exit(3)
	}
	if json.NewEncoder(os.Stdout).Encode(credential) != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

func certificateFiles(t *testing.T, root string) (CertificateFiles, []byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "exec fixture issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"managed.example.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
		cert, err := x509.CreateCertificate(rand.Reader, leaf, ca, &private.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		encodedKey, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})
	}
	cert, private := issue(2, x509.ExtKeyUsageClientAuth)
	files := CertificateFiles{filepath.Join(root, "client.pem"), filepath.Join(root, "client-key.pem")}
	if os.WriteFile(files.CertificateFile, cert, 0o600) != nil || os.WriteFile(files.KeyFile, private, 0o600) != nil {
		t.Fatal("write client material")
	}
	serverPEM, serverKey := issue(3, x509.ExtKeyUsageServerAuth)
	server, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	return files, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), server
}

func TestClientGoExecComposesCertificateAndToken(t *testing.T) {
	root := privateTemp(t)
	files, ca, server := certificateFiles(t, root)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 || r.Header.Get("Authorization") != "Bearer cluster-token" {
			http.Error(w, "missing independent credentials", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(204)
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	target.StartTLS()
	defer target.Close()
	tokenPath := filepath.Join(root, "token")
	if os.WriteFile(tokenPath, []byte("cluster-token"), 0o600) != nil {
		t.Fatal("write token")
	}
	profile := Profile{Owner: options().Owner, StateDir: root, Public: true, Source: Source{TokenFile: tokenPath}, Certificate: &files}
	path, err := WriteProfile(t.Context(), profile)
	if err != nil {
		t.Fatal(err)
	}
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client, err := rest.HTTPClientFor(&rest.Config{Host: target.URL, TLSClientConfig: rest.TLSClientConfig{ServerName: "managed.example.test", CAData: ca}, ExecProvider: &clientcmdapi.ExecConfig{Command: command, Args: []string{"-test.run=^TestCredentialExecHelper$", "-tnl-kube-credential-profile=" + path}, APIVersion: "client.authentication.k8s.io/v1", InteractiveMode: clientcmdapi.NeverExecInteractiveMode}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), "GET", target.URL+"/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("client-go failed composed exec authentication:", err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("client-go did not use both credentials")
	}
	credential, err := Credential(t.Context(), profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Status.ExpirationTimestamp == nil || credential.APIVersion != "client.authentication.k8s.io/v1" {
		t.Fatal("missing combined credential expiry")
	}
}

func TestSelectedUserPreservesTokenPathAndRejectsClientCertForwarding(t *testing.T) {
	root := privateTemp(t)
	if os.WriteFile(filepath.Join(root, "token"), []byte("one"), 0o600) != nil {
		t.Fatal("write token")
	}
	path := filepath.Join(root, "source")
	input := "apiVersion: v1\nkind: Config\nusers:\n- name: selected\n  user:\n    tokenFile: token\n- name: unselected\n  user:\n    exec:\n      command: /never/execute\n"
	if os.WriteFile(path, []byte(input), 0o600) != nil {
		t.Fatal("write source")
	}
	source := Source{ConfigFile: path, ExistingUser: "selected"}
	first, err := source.Token(t.Context())
	if err != nil || first.Value != "one" {
		t.Fatal("relative token path was not retained")
	}
	if os.WriteFile(filepath.Join(root, "token"), []byte("two"), 0o600) != nil {
		t.Fatal("rotate token")
	}
	second, err := source.Token(t.Context())
	if err != nil || second.Value != "two" {
		t.Fatal("rotated token file was cached")
	}
	input = strings.Replace(input, "tokenFile: token", "client-certificate: client.pem", 1)
	if os.WriteFile(path, []byte(input), 0o600) != nil {
		t.Fatal("replace source")
	}
	if _, err := source.Token(t.Context()); err == nil {
		t.Fatal("claimed end-to-end client certificate forwarding")
	}
}

func TestCredentialKeepsSecretsOutOfPreparationMetadata(t *testing.T) {
	root := privateTemp(t)
	path := filepath.Join(root, "token")
	if os.WriteFile(path, []byte("not-public"), 0o600) != nil {
		t.Fatal("write token")
	}
	o := options()
	result, err := PrepareConnection(t.Context(), Plan{Path: filepath.Join(root, "config")}, o, Profile{Owner: o.Owner, StateDir: root, Source: Source{TokenFile: path}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "not-public") || strings.Contains(string(data), "certificate_data") {
		t.Fatal("credential exposed in metadata")
	}
	f, err := os.Open(result.File)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err = io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "not-public") {
		t.Fatal("credential embedded in kubeconfig")
	}
}

func TestEKSGetTokenExecProcess(t *testing.T) {
	args := flag.Args()
	if len(args) == 0 || args[0] != "eks" {
		return
	}
	if strings.Join(args, " ") != "eks get-token --cluster-name shop --region us-east-1 --output json" {
		os.Exit(5)
	}
	result := credentialv1.ExecCredential{TypeMeta: metav1.TypeMeta{Kind: "ExecCredential", APIVersion: "client.authentication.k8s.io/v1beta1"}, Status: &credentialv1.ExecCredentialStatus{Token: "eks-fixture-token", ExpirationTimestamp: &metav1.Time{Time: time.Now().Add(5 * time.Minute)}}}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(6)
	}
	os.Exit(0)
}

func TestEKSPreparationDoesNotCallAWSAndComposesFreshToken(t *testing.T) {
	root := privateTemp(t)
	files, _, _ := certificateFiles(t, root)
	o := options()
	profile := Profile{Owner: o.Owner, StateDir: root, Public: true, Certificate: &files, Source: Source{EKS: &EKS{Cluster: "shop", Region: "us-east-1"}}}
	// preparation works with no AWS binary or credentials at all.
	t.Setenv("PATH", root)
	if _, err := PrepareConnection(t.Context(), Plan{Path: filepath.Join(root, "config")}, o, profile); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// the executable fixture proves the exact standard AWS get-token invocation.
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(binary, "'", "'\\''") + "' -test.run=^TestEKSGetTokenExecProcess$ -- \"$@\"\n"
	if os.WriteFile(filepath.Join(root, "aws"), []byte(script), 0o700) != nil {
		t.Fatal("write AWS runner fixture")
	}
	for range 2 {
		result, err := Credential(t.Context(), profile, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Status.Token != "eks-fixture-token" || result.Status.ClientCertificateData == "" || result.Status.ClientKeyData == "" || result.Status.ExpirationTimestamp == nil || time.Until(result.Status.ExpirationTimestamp.Time) > 5*time.Minute {
			t.Fatal("EKS token and mTLS material were not composed with the earlier expiry")
		}
	}
}

func TestCredentialProfilesDoNotReplaceExistingContextCredentials(t *testing.T) {
	root := privateTemp(t)
	profile := Profile{Owner: options().Owner, StateDir: root, Source: Source{TokenFile: filepath.Join(root, "first-token")}}
	first, err := WriteProfile(t.Context(), profile)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	profile.Source.TokenFile = filepath.Join(root, "second-token")
	second, err := WriteProfile(t.Context(), profile)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !bytes.Equal(before, after) {
		t.Fatal("new credential source replaced a live context's immutable profile")
	}
}
