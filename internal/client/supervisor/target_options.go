package supervisor

import publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"

// TargetOptions uses the job's captured trust without reopening project files.
func TargetOptions(job Job) (publisherproxy.TargetOptions, error) {
	roots, err := trustRoots(job.TargetCAPEM)
	return publisherproxy.TargetOptions{RootCAs: roots, ServerName: job.TargetTLSName}, err
}
