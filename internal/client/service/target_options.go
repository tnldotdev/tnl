package publisherjob

import localproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"

// TargetOptions uses the job's captured trust without reopening project files.
func TargetOptions(job Job) (localproxy.TargetOptions, error) {
	roots, err := trustRoots(job.TargetCAPEM)
	return localproxy.TargetOptions{RootCAs: roots, ServerName: job.TargetTLSName}, err
}
