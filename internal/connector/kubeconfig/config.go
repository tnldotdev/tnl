// package kubeconfig prepares owned contexts without selecting a global context.
package kubeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/tnldotdev/tnl/internal/client/filelock"
	serviceconfig "github.com/tnldotdev/tnl/internal/config"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/runtime"
	kubev1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

var (
	ErrConfig    = errors.New("kubeconfig cannot be updated safely; choose a separate kubeconfig file")
	ErrCollision = errors.New("kubeconfig context belongs to another installation; choose a qualified context name")
)

const maxConfig = 4 << 20
const ownerExtension = "tnl.dev/owner"

// Owner is the immutable boundary of one connection. display names cannot prove
// ownership, including when two installations happen to use the same hostname.
type Owner struct {
	ControlURL string `json:"control_url"`
	TeamID     string `json:"team_id"`
	SourceID   string `json:"source_id"`
	ServiceID  string `json:"service_id"`
}

type Plan struct {
	Path          string   `json:"path"`
	SearchPaths   []string `json:"-"`
	SelectContext bool     `json:"-"`
	Exclusive     bool     `json:"-"`
}

// PlanLocal uses the first nonempty KUBECONFIG path as its writable destination.
// other files participate in collision checks without moving path references.
func PlanLocal(home, kubeconfig string) (Plan, error) {
	paths := filepath.SplitList(kubeconfig)
	if kubeconfig == "" {
		paths = []string{filepath.Join(home, ".kube", "config")}
	}
	var p Plan
	for _, path := range paths {
		if path == "" {
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return Plan{}, ErrConfig
		}
		p.SearchPaths = append(p.SearchPaths, absolute)
	}
	if len(p.SearchPaths) == 0 {
		return Plan{}, ErrConfig
	}
	p.Path = p.SearchPaths[0]
	return p, nil
}

// PlanSession creates only a new private file under the supplied runner temp
// directory. the caller owns exporting KUBECONFIG and removing returned files.
func PlanSession(runnerTemp, sessionID string) (Plan, error) {
	if !label.MatchString(sessionID) || !filepath.IsAbs(runnerTemp) {
		return Plan{}, ErrConfig
	}
	path := filepath.Join(runnerTemp, "tnl-kube-"+sessionID+".yaml")
	return Plan{Path: path, SearchPaths: []string{path}, SelectContext: true, Exclusive: true}, nil
}

type Options struct {
	Owner        Owner
	ProjectLabel string
	Service      string
	Namespace    string
	Server       string
	// TLSServerName is the managed tnl WebPKI hostname, even for loopback clients.
	TLSServerName string
	Helper        string
	Profile       string
	// CredentialArgs selects the same native owner's private credential helper.
	CredentialArgs []string
}

type Result struct {
	Protocol     serviceconfig.ProtocolName `json:"protocol"`
	File         string                     `json:"file"`
	Context      string                     `json:"context"`
	Namespace    string                     `json:"namespace,omitempty"`
	Qualified    bool                       `json:"qualified"`
	Files        []string                   `json:"files"`
	configDigest [32]byte
}

var label = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var namespace = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func (o Options) validate() error {
	u, err := url.Parse(o.Server)
	control, controlErr := url.Parse(o.Owner.ControlURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" ||
		controlErr != nil || control.Scheme != "https" || control.Host == "" || control.User != nil || control.RawQuery != "" || control.Fragment != "" ||
		o.Owner.TeamID == "" || o.Owner.SourceID == "" || o.Owner.ServiceID == "" || !label.MatchString(o.ProjectLabel) || !label.MatchString(o.Service) ||
		o.Namespace != "" && !namespace.MatchString(o.Namespace) || !serviceconfig.ValidTLSIdentity(o.TLSServerName) || !filepath.IsAbs(o.Helper) || !filepath.IsAbs(o.Profile) {
		return ErrConfig
	}
	return nil
}

// Prepare uses a locked read-modify-write and edits only owned named entries.
// YAML nodes preserve unknown fields, comments and relative path references in
// unrelated entries. aliases, merge keys and duplicate keys fail closed.
func (p Plan) Prepare(ctx context.Context, o Options) (Result, error) {
	var result Result
	if o.validate() != nil || !filepath.IsAbs(p.Path) {
		return result, ErrConfig
	}
	if err := safeParent(p.Path, true); err != nil {
		return result, err
	}
	lock, err := filelock.AcquireContext(ctx, p.Path+".tnl-lock", os.Getuid())
	if err != nil {
		return result, errors.Join(ErrConfig, err)
	}
	defer lock.Close()
	original, info, err := readSafe(p.Path)
	if err != nil {
		return result, err
	}
	if p.Exclusive && info != nil {
		return result, ErrCollision
	}
	root, err := parse(original)
	if err != nil {
		return result, err
	}
	all := []*yaml.Node{root}
	for _, path := range p.SearchPaths {
		if path == p.Path {
			continue
		}
		data, _, err := readSafe(path)
		if err != nil {
			return result, err
		}
		node, err := parse(data)
		if err != nil {
			return result, err
		}
		all = append(all, node)
	}
	name := "tnl:" + o.ProjectLabel + "/" + o.Service
	available := func(name string) bool {
		for _, node := range all {
			for _, section := range []string{"clusters", "users", "contexts"} {
				for _, entry := range sequence(node, section) {
					if scalar(entry, "name") == name && !owned(entry, section, o.Owner) {
						return false
					}
				}
			}
		}
		return true
	}
	if !available(name) {
		encoded, _ := json.Marshal(o.Owner)
		digest := sha256.Sum256(encoded)
		name += ":" + hex.EncodeToString(digest[:6])
		result.Qualified = true
		if !available(name) {
			return result, ErrCollision
		}
	}
	encoded, _ := json.Marshal(o.Owner)
	extensions := []kubev1.NamedExtension{{Name: ownerExtension, Extension: runtime.RawExtension{Raw: encoded}}}
	if o.Namespace == "" {
		for _, node := range all {
			for _, entry := range sequence(node, "contexts") {
				if scalar(entry, "name") == name && owned(entry, "contexts", o.Owner) {
					o.Namespace = scalar(field(entry, "context"), "namespace")
					break
				}
			}
		}
	}
	if o.Namespace != "" && !namespace.MatchString(o.Namespace) {
		return result, ErrConfig
	}
	config := kubev1.Config{APIVersion: "v1", Kind: "Config",
		Clusters:  []kubev1.NamedCluster{{Name: name, Cluster: kubev1.Cluster{Server: o.Server, TLSServerName: o.TLSServerName, Extensions: extensions}}},
		AuthInfos: []kubev1.NamedAuthInfo{{Name: name, AuthInfo: kubev1.AuthInfo{Exec: &kubev1.ExecConfig{APIVersion: "client.authentication.k8s.io/v1", Command: o.Helper, Args: []string{"connect", "kube-credential", "--profile", o.Profile}, InteractiveMode: "Never"}, Extensions: extensions}}},
		Contexts:  []kubev1.NamedContext{{Name: name, Context: kubev1.Context{Cluster: name, AuthInfo: name, Namespace: o.Namespace, Extensions: extensions}}},
	}
	if o.CredentialArgs != nil {
		config.AuthInfos[0].AuthInfo.Exec.Args = o.CredentialArgs
	}
	data, err := json.Marshal(config)
	if err != nil {
		return result, ErrConfig
	}
	generated, err := parse(data)
	if err != nil {
		return result, err
	}
	plainStyle(generated)
	for _, section := range []string{"clusters", "users", "contexts"} {
		entry := sequence(generated, section)[0]
		seq := field(root, section)
		if seq == nil || seq.Tag == "!!null" {
			seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			set(root, section, seq)
		}
		replaced := false
		for i, old := range seq.Content {
			if scalar(old, "name") == name {
				seq.Content[i] = updateOwned(old, entry, section)
				replaced = true
				break
			}
		}
		if !replaced {
			seq.Content = append(seq.Content, entry)
		}
	}
	if p.SelectContext {
		set(root, "current-context", text(name))
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if encoder.Encode(root) != nil || encoder.Close() != nil {
		return result, ErrConfig
	}
	if err := replace(p.Path, original, info, output.Bytes()); err != nil {
		return result, err
	}
	result.Protocol, result.File, result.Context, result.Namespace = serviceconfig.ProtocolKubernetes, p.Path, name, o.Namespace
	result.Files = []string{p.Path, o.Profile}
	result.configDigest = sha256.Sum256(output.Bytes())
	return result, nil
}

func plainStyle(node *yaml.Node) {
	node.Style = 0
	for _, child := range node.Content {
		plainStyle(child)
	}
}

// CleanupSession removes the exact session file prepared by this process. a
// changed file is user work and is retained. protected profiles belong to the
// caller's state directory, whose lifetime may span more than one context.
func (p Plan) CleanupSession(ctx context.Context, result Result) error {
	if !p.Exclusive || !p.SelectContext || p.Path != result.File || result.configDigest == ([32]byte{}) {
		return ErrConfig
	}
	lock, err := filelock.AcquireContext(ctx, p.Path+".tnl-lock", os.Getuid())
	if err != nil {
		return err
	}
	defer lock.Close()
	data, info, err := readSafe(p.Path)
	if err != nil {
		return err
	}
	if info == nil {
		return nil
	}
	if sha256.Sum256(data) != result.configDigest {
		return ErrConfig
	}
	return os.Remove(p.Path)
}

func updateOwned(old, generated *yaml.Node, section string) *yaml.Node {
	kind := map[string]string{"clusters": "cluster", "users": "user", "contexts": "context"}[section]
	object, next := field(old, kind), field(generated, kind)
	if object == nil || object.Kind != yaml.MappingNode {
		return generated
	}
	// old static credentials or trust must not bypass the new exec helper or the
	// managed WebPKI identity. retain fields outside those owned boundaries.
	remove := map[string][]string{
		"clusters": {"certificate-authority", "certificate-authority-data", "insecure-skip-tls-verify", "proxy-url"},
		"users":    {"client-certificate", "client-certificate-data", "client-key", "client-key-data", "token", "tokenFile", "auth-provider", "username", "password", "as", "as-uid", "as-groups", "as-user-extra"},
	}[section]
	for _, key := range remove {
		for i := 0; i < len(object.Content); i += 2 {
			if object.Content[i].Value == key {
				object.Content = append(object.Content[:i], object.Content[i+2:]...)
				break
			}
		}
	}
	for i := 0; i < len(next.Content); i += 2 {
		key, value := next.Content[i].Value, next.Content[i+1]
		if key == "extensions" {
			extensions := field(object, key)
			if extensions != nil && extensions.Kind == yaml.SequenceNode {
				found := false
				for j, e := range extensions.Content {
					if scalar(e, "name") == ownerExtension {
						extensions.Content[j] = value.Content[0]
						found = true
						break
					}
				}
				if !found {
					extensions.Content = append(extensions.Content, value.Content...)
				}
				continue
			}
		}
		if previous := field(object, key); previous != nil {
			value.HeadComment, value.LineComment, value.FootComment = previous.HeadComment, previous.LineComment, previous.FootComment
		}
		set(object, key, value)
	}
	return old
}

func parse(data []byte) (*yaml.Node, error) {
	if len(data) == 0 {
		data = []byte("apiVersion: v1\nkind: Config\n")
	}
	if len(data) > maxConfig {
		return nil, ErrConfig
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&document) != nil || len(document.Content) != 1 {
		return nil, ErrConfig
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrConfig
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || !validNode(root, 0) {
		return nil, ErrConfig
	}
	for _, section := range []string{"clusters", "users", "contexts"} {
		seq := field(root, section)
		if seq == nil || seq.Tag == "!!null" {
			continue
		}
		if seq.Kind != yaml.SequenceNode {
			return nil, ErrConfig
		}
		seen := map[string]bool{}
		for _, entry := range seq.Content {
			name := scalar(entry, "name")
			if name == "" || seen[name] {
				return nil, ErrConfig
			}
			seen[name] = true
		}
	}
	if scalar(root, "apiVersion") != "v1" || scalar(root, "kind") != "Config" {
		return nil, ErrConfig
	}
	return root, nil
}

func validNode(n *yaml.Node, depth int) bool {
	if depth > 64 || n.Anchor != "" || n.Kind == yaml.AliasNode {
		return false
	}
	switch n.Tag {
	case "!!map", "!!seq", "!!str", "!!null", "!!bool", "!!int", "!!float":
	default:
		return false
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
				return false
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if !validNode(child, depth+1) {
			return false
		}
	}
	return true
}

func field(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func scalar(n *yaml.Node, key string) string {
	v := field(n, key)
	if v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}
func text(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}
func set(n *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content, text(key), value)
}
func sequence(n *yaml.Node, key string) []*yaml.Node {
	if seq := field(n, key); seq != nil && seq.Kind == yaml.SequenceNode {
		return seq.Content
	}
	return nil
}
func owned(entry *yaml.Node, section string, owner Owner) bool {
	kind := map[string]string{"clusters": "cluster", "users": "user", "contexts": "context"}[section]
	for _, extension := range sequence(field(entry, kind), "extensions") {
		if scalar(extension, "name") != ownerExtension {
			continue
		}
		var value Owner
		n := field(extension, "extension")
		if n == nil {
			return false
		}
		encoded, err := nodeJSON(n)
		if err != nil || json.Unmarshal(encoded, &value) != nil {
			return false
		}
		return owner == value
	}
	return false
}
func nodeJSON(n *yaml.Node) ([]byte, error) {
	var value any
	if err := n.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func safeParent(path string, create bool) error {
	parent := filepath.Dir(path)
	// check every existing ancestor before mkdir; never follow a user symlink.
	for dir := parent; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return ErrConfig
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrConfig, err)
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	if create {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return errors.Join(ErrConfig, err)
		}
	}
	return nil
}

func readSafe(path string) ([]byte, os.FileInfo, error) {
	if safeParent(path, false) != nil {
		return nil, nil, ErrConfig
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, errors.Join(ErrConfig, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, ErrConfig
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0o022 != 0 || info.Size() > maxConfig {
		return nil, nil, ErrConfig
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	if err != nil || len(data) > maxConfig {
		return nil, nil, ErrConfig
	}
	return data, info, nil
}

func replace(path string, original []byte, info os.FileInfo, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".tnl-kube-*")
	if err != nil {
		return errors.Join(ErrConfig, err)
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if _, err = temp.Write(data); err != nil {
		return errors.Join(ErrConfig, err)
	}
	if err = temp.Sync(); err != nil {
		return errors.Join(ErrConfig, err)
	}
	current, currentInfo, err := readSafe(path)
	if err != nil || !bytes.Equal(original, current) || (info == nil) != (currentInfo == nil) || info != nil && !os.SameFile(info, currentInfo) {
		return ErrConfig
	}
	if info == nil {
		// link is an atomic no-replace publication of a new file.
		err = os.Link(temp.Name(), path)
	} else {
		err = os.Rename(temp.Name(), path)
	}
	if err != nil {
		return errors.Join(ErrConfig, err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
