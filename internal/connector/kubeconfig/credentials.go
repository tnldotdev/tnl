package kubeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/client/filelock"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	kubev1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

var ErrCredential = errors.New("kubernetes credential is unavailable or expired; select a Kubernetes user or refresh its token")

var region = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-[0-9]+$`)

func acquireProfileLock(ctx context.Context, path string) (*filelock.Lock, error) {
	return filelock.AcquireContext(ctx, path+".lock", os.Getuid())
}

type EKS struct {
	Cluster string `json:"cluster"`
	Region  string `json:"region"`
	RoleARN string `json:"role_arn,omitempty"`
}

// Source is explicitly selected by the caller. no project declaration may cause
// an arbitrary kubeconfig exec command to run. ExistingUser is opt-in and exact.
type Source struct {
	EKS          *EKS   `json:"eks,omitempty"`
	ConfigFile   string `json:"config_file,omitempty"`
	ExistingUser string `json:"existing_user,omitempty"`
	TokenFile    string `json:"token_file,omitempty"`
}

// ResolveSource prepares paths and applies an approved hint only when the caller
// selected no source. token reads and exec commands remain credential-time work.
func ResolveSource(source Source, hint *controlv1.KubernetesAuth) (Source, error) {
	var err error
	if source.ConfigFile != "" {
		source.ConfigFile, err = filepath.Abs(source.ConfigFile)
		if err != nil {
			return Source{}, err
		}
	}
	if source.TokenFile != "" {
		source.TokenFile, err = filepath.Abs(source.TokenFile)
		if err != nil {
			return Source{}, err
		}
	}
	if source.EKS == nil && source.ConfigFile == "" && source.ExistingUser == "" && source.TokenFile == "" && hint != nil {
		if hint.Provider != controlv1.KubernetesEKS {
			return Source{}, ErrCredential
		}
		source.EKS = &EKS{Cluster: hint.Cluster, Region: hint.Region}
	}
	if err := source.Validate(); err != nil {
		return Source{}, err
	}
	return source, nil
}

type CertificateFiles struct {
	CertificateFile string `json:"certificate_file"`
	KeyFile         string `json:"key_file"`
}

// Profile is private native state. kubeconfig contains only its absolute path.
// renewed certificate material is obtained by the helper's caller, not embedded
// as static kubeconfig client-certificate fields (which bypass exec in client-go).
type Profile struct {
	Owner       Owner             `json:"owner"`
	StateDir    string            `json:"state_dir"`
	IdentityID  string            `json:"identity_id,omitempty"`
	Public      bool              `json:"public"`
	Source      Source            `json:"source"`
	Certificate *CertificateFiles `json:"certificate,omitempty"`
}

func (Profile) String() string   { return "private kubernetes credential profile" }
func (Profile) GoString() string { return "private kubernetes credential profile" }

func (s Source) Validate() error {
	n := 0
	if s.EKS != nil {
		n++
		if !label.MatchString(s.EKS.Cluster) || !region.MatchString(s.EKS.Region) || strings.ContainsAny(s.EKS.RoleARN, "\x00\r\n") {
			return ErrCredential
		}
	}
	if s.ConfigFile != "" || s.ExistingUser != "" {
		n++
		if !filepath.IsAbs(s.ConfigFile) || s.ExistingUser == "" || len(s.ExistingUser) > 1024 {
			return ErrCredential
		}
	}
	if s.TokenFile != "" {
		n++
		if !filepath.IsAbs(s.TokenFile) {
			return ErrCredential
		}
	}
	if n != 1 {
		return ErrCredential
	}
	return nil
}

// WriteProfile writes only into a private client-state subdirectory and checks
// ownership on replacement. it does not invoke AWS or a selected exec plugin.
func WriteProfile(ctx context.Context, profile Profile) (string, error) {
	if profile.Source.Validate() != nil || !filepath.IsAbs(profile.StateDir) {
		return "", ErrCredential
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return "", ErrCredential
	}
	// immutable, content-addressed profiles keep a failed kubeconfig update from
	// replacing credentials already referenced by another live context.
	digest := sha256.Sum256(data)
	path := filepath.Join(profile.StateDir, "kubernetes", hex.EncodeToString(digest[:])+".json")
	if err := safeParent(path, true); err != nil {
		return "", err
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || info.Mode().Perm() != 0o700 {
		return "", ErrConfig
	}
	lock, err := acquireProfileLock(ctx, path)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	original, info, err := readSafe(path)
	if err != nil {
		return "", err
	}
	if info != nil {
		var old Profile
		if json.Unmarshal(original, &old) != nil || old.Owner != profile.Owner || !bytes.Equal(original, data) {
			return "", ErrCollision
		}
		return path, nil
	}
	if err := replace(path, original, info, data); err != nil {
		return "", err
	}
	return path, nil
}

func ReadProfile(path string) (Profile, error) {
	var profile Profile
	data, info, err := readSafe(path)
	if err != nil || info == nil || info.Mode().Perm() != 0o600 {
		return profile, ErrCredential
	}
	if json.Unmarshal(data, &profile) != nil || profile.Source.Validate() != nil {
		return Profile{}, ErrCredential
	}
	return profile, nil
}

// PrepareConnection is the shared local/CI per-context preparation boundary.
// callers export result.File if needed; only session plans select current-context.
func PrepareConnection(ctx context.Context, plan Plan, options Options, profile Profile) (Result, error) {
	if options.Owner != profile.Owner {
		return Result{}, ErrConfig
	}
	path, err := WriteProfile(ctx, profile)
	if err != nil {
		return Result{}, err
	}
	options.Profile = path
	return plan.Prepare(ctx, options)
}

// Token is a Kubernetes bearer credential, independent of tnl admission.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

func (Token) String() string   { return "kubernetes bearer credential" }
func (Token) GoString() string { return "kubernetes bearer credential" }

type IssueCertificate func(context.Context) (CertificateFiles, error)

// Credential emits one v1 ExecCredential containing BOTH the tnl mTLS material
// and cluster token. client-go must not see static client cert/key fields.
func Credential(ctx context.Context, profile Profile, issue IssueCertificate) (credentialv1.ExecCredential, error) {
	result := credentialv1.ExecCredential{TypeMeta: metav1.TypeMeta{Kind: "ExecCredential", APIVersion: "client.authentication.k8s.io/v1"}, Status: &credentialv1.ExecCredentialStatus{}}
	token, err := profile.Source.Token(ctx)
	if err != nil {
		return credentialv1.ExecCredential{}, err
	}
	result.Status.Token = token.Value
	expires := token.ExpiresAt
	if profile.Public {
		files := profile.Certificate
		if issue != nil {
			current, err := issue(ctx)
			if err != nil {
				return credentialv1.ExecCredential{}, err
			}
			files = &current
		}
		if files == nil {
			return credentialv1.ExecCredential{}, ErrCredential
		}
		cert, _, err := readSafe(files.CertificateFile)
		if err != nil {
			return credentialv1.ExecCredential{}, ErrCredential
		}
		key, info, err := readSafe(files.KeyFile)
		if err != nil || info == nil || info.Mode().Perm() != 0o600 {
			return credentialv1.ExecCredential{}, ErrCredential
		}
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil || len(pair.Certificate) == 0 {
			return credentialv1.ExecCredential{}, ErrCredential
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || !leaf.NotAfter.After(time.Now()) || leaf.NotBefore.After(time.Now()) {
			return credentialv1.ExecCredential{}, ErrCredential
		}
		result.Status.ClientCertificateData, result.Status.ClientKeyData = string(cert), string(key)
		if expires.IsZero() || leaf.NotAfter.Before(expires) {
			expires = leaf.NotAfter
		}
	}
	if !expires.IsZero() {
		if !expires.After(time.Now()) {
			return credentialv1.ExecCredential{}, ErrCredential
		}
		result.Status.ExpirationTimestamp = &metav1.Time{Time: expires}
	}
	if result.Status.Token == "" && result.Status.ClientCertificateData == "" {
		return credentialv1.ExecCredential{}, ErrCredential
	}
	return result, nil
}

func (s Source) Token(ctx context.Context) (Token, error) {
	if s.Validate() != nil {
		return Token{}, ErrCredential
	}
	if s.EKS != nil {
		// only get-token runs on the client. role credentials follow the standard
		// AWS chain; no DescribeCluster call or cloud discovery happens at connect.
		command, err := exec.LookPath("aws")
		if err != nil {
			return Token{}, ErrCredential
		}
		command, err = filepath.Abs(command)
		if err != nil {
			return Token{}, ErrCredential
		}
		args := []string{"eks", "get-token", "--cluster-name", s.EKS.Cluster, "--region", s.EKS.Region, "--output", "json"}
		if s.EKS.RoleARN != "" {
			args = append(args, "--role-arn", s.EKS.RoleARN)
		}
		return execToken(ctx, command, args, nil, "")
	}
	if s.TokenFile != "" {
		data, info, err := readSafe(s.TokenFile)
		if err != nil || info == nil || info.Mode().Perm() != 0o600 {
			return Token{}, ErrCredential
		}
		return checkedToken(strings.TrimSpace(string(data)), time.Time{})
	}
	if s.ConfigFile == "" {
		return Token{}, nil
	}
	data, _, err := readSafe(s.ConfigFile)
	if err != nil {
		return Token{}, ErrCredential
	}
	root, err := parse(data)
	if err != nil {
		return Token{}, ErrCredential
	}
	encoded, err := nodeJSON(root)
	if err != nil {
		return Token{}, ErrCredential
	}
	var config kubev1.Config
	if json.Unmarshal(encoded, &config) != nil {
		return Token{}, ErrCredential
	}
	var user *kubev1.AuthInfo
	for i := range config.AuthInfos {
		if config.AuthInfos[i].Name == s.ExistingUser {
			user = &config.AuthInfos[i].AuthInfo
		}
	}
	if user == nil || user.ClientCertificate != "" || len(user.ClientCertificateData) > 0 || user.ClientKey != "" || len(user.ClientKeyData) > 0 || user.AuthProvider != nil || user.Username != "" || user.Password != "" {
		return Token{}, ErrCredential
	}
	if user.TokenFile != "" {
		path := user.TokenFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(s.ConfigFile), path)
		}
		return (Source{TokenFile: path}).Token(ctx)
	}
	if user.Token != "" {
		return checkedToken(user.Token, time.Time{})
	}
	if user.Exec == nil {
		return Token{}, ErrCredential
	}
	plugin := user.Exec
	if plugin.InteractiveMode != "Never" && plugin.InteractiveMode != "IfAvailable" && plugin.InteractiveMode != "" || plugin.APIVersion != "client.authentication.k8s.io/v1" && plugin.APIVersion != "client.authentication.k8s.io/v1beta1" || plugin.ProvideClusterInfo {
		return Token{}, ErrCredential
	}
	command := plugin.Command
	if strings.ContainsRune(command, filepath.Separator) && !filepath.IsAbs(command) {
		command = filepath.Join(filepath.Dir(s.ConfigFile), command)
	}
	command, err = exec.LookPath(command)
	if err != nil {
		return Token{}, ErrCredential
	}
	command, err = filepath.Abs(command)
	if err != nil {
		return Token{}, ErrCredential
	}
	env := make([]string, 0, len(plugin.Env))
	for _, e := range plugin.Env {
		if e.Name == "KUBERNETES_EXEC_INFO" || strings.ContainsAny(e.Name, "=\x00") {
			return Token{}, ErrCredential
		}
		env = append(env, e.Name+"="+e.Value)
	}
	info := `{"apiVersion":"` + plugin.APIVersion + `","kind":"ExecCredential","spec":{"interactive":false}}`
	return execToken(ctx, command, plugin.Args, env, info)
}

func checkedToken(value string, expires time.Time) (Token, error) {
	if value == "" || len(value) > 1<<20 || strings.ContainsAny(value, "\x00\r\n \t") || !expires.IsZero() && !expires.After(time.Now()) {
		return Token{}, ErrCredential
	}
	return Token{Value: value, ExpiresAt: expires}, nil
}

func execToken(ctx context.Context, command string, args, env []string, info string) (Token, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.WaitDelay = time.Second
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "KUBERNETES_EXEC_INFO=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	if info != "" {
		cmd.Env = append(cmd.Env, "KUBERNETES_EXEC_INFO="+info)
	}
	var output limitedOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if cmd.Run() != nil {
		return Token{}, ErrCredential
	}
	var result credentialv1.ExecCredential
	if json.Unmarshal(output.buffer.Bytes(), &result) != nil || result.Kind != "ExecCredential" || result.APIVersion != "client.authentication.k8s.io/v1" && result.APIVersion != "client.authentication.k8s.io/v1beta1" || result.Status == nil || result.Status.ClientCertificateData != "" || result.Status.ClientKeyData != "" {
		return Token{}, ErrCredential
	}
	var expires time.Time
	if result.Status.ExpirationTimestamp != nil {
		expires = result.Status.ExpirationTimestamp.Time
	}
	return checkedToken(result.Status.Token, expires)
}

type limitedOutput struct{ buffer bytes.Buffer }

func (b *limitedOutput) Write(data []byte) (int, error) {
	if len(data) > 1<<20-b.buffer.Len() {
		return 0, ErrCredential
	}
	return b.buffer.Write(data)
}
