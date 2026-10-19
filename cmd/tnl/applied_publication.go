package main

import (
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func assignedTargetTrust(job *publisherjob.Job, trust *controlv1.ProjectTargetTLS) error {
	if trust == nil {
		if job.Kind == publisherjob.KindPrivateService && job.Trust != nil {
			return publisherjob.ErrScope
		}
		return nil
	}
	snapshot := projectconfig.TargetTrustSnapshot{Hostname: trust.Hostname, Digest: trust.Digest}
	if trust.CaPem != nil {
		snapshot.CAPEM = []byte(*trust.CaPem)
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	if job.Kind == publisherjob.KindPrivateService {
		captured, err := snapshot.PrivateSnapshot()
		if err != nil {
			return err
		}
		if job.Trust != nil && job.Trust.Digest != captured.Digest {
			return publisherjob.ErrScope
		}
		job.Trust = captured
		return nil
	}
	job.TargetTLSName, job.TargetCAPEM = snapshot.Hostname, snapshot.CAPEM
	return nil
}
