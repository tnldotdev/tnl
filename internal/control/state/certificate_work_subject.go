package state

import "math"

type CertificateSubjectKind string

const (
	CertificateSubjectPublicURL CertificateSubjectKind = "public_url"
	CertificateSubjectService   CertificateSubjectKind = "service"
)

// CertificateSubject binds one certificate order to exactly one service and run.
// IDs remain opaque; the discriminator, rather than an ID prefix, selects SQL.
type CertificateSubject struct {
	Kind      CertificateSubjectKind
	ID        string
	RunID     string
	RunNumber uint64
}

func (s CertificateSubject) Valid() bool {
	return (s.Kind == CertificateSubjectPublicURL || s.Kind == CertificateSubjectService) &&
		validStateText(s.ID) && validStateText(s.RunID) && s.RunNumber > 0 && s.RunNumber <= math.MaxInt64
}

func certificateSubject(publicURL, publicRun string, publicNumber int64, service, serviceRun string, privateNumber int64) (CertificateSubject, error) {
	var subject CertificateSubject
	switch {
	case service == "" && serviceRun == "" && privateNumber == 0 && publicNumber > 0:
		subject = CertificateSubject{Kind: CertificateSubjectPublicURL, ID: publicURL, RunID: publicRun, RunNumber: uint64(publicNumber)}
	case publicURL == "" && publicRun == "" && publicNumber == 0 && privateNumber > 0:
		subject = CertificateSubject{Kind: CertificateSubjectService, ID: service, RunID: serviceRun, RunNumber: uint64(privateNumber)}
	default:
		return CertificateSubject{}, ErrCertificateIssuanceInvalid
	}
	if !subject.Valid() {
		return CertificateSubject{}, ErrCertificateIssuanceInvalid
	}
	return subject, nil
}

type acmeWorkBinding struct {
	orderRevision, workerEpoch int64
}

func checkedACMEWorkBinding(revision, epoch uint64) (acmeWorkBinding, error) {
	// save increments order_revision in SQL. work_epoch is compared exactly and
	// must not be clamped or reinterpreted as another worker's lease.
	if revision == 0 || revision >= math.MaxInt64 || epoch == 0 || epoch > math.MaxInt64 {
		return acmeWorkBinding{}, ErrCertificateIssuanceInvalid
	}
	return acmeWorkBinding{orderRevision: int64(revision), workerEpoch: int64(epoch)}, nil
}
