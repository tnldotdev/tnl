package controlstate

import "math"

type CertificateSubjectKind string

const (
	CertificateSubjectPublicURL      CertificateSubjectKind = "public_url"
	CertificateSubjectManagedService CertificateSubjectKind = "managed_service"
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
	return (s.Kind == CertificateSubjectPublicURL || s.Kind == CertificateSubjectManagedService) &&
		validStateText(s.ID) && validStateText(s.RunID) && s.RunNumber > 0 && s.RunNumber <= math.MaxInt64
}

func certificateSubject(publicURL, publicRun string, publicNumber int64, service, privateRun string, privateNumber int64) (CertificateSubject, error) {
	var subject CertificateSubject
	switch {
	case service == "" && privateRun == "" && privateNumber == 0 && publicNumber > 0:
		subject = CertificateSubject{Kind: CertificateSubjectPublicURL, ID: publicURL, RunID: publicRun, RunNumber: uint64(publicNumber)}
	case publicURL == "" && publicRun == "" && publicNumber == 0 && privateNumber > 0:
		subject = CertificateSubject{Kind: CertificateSubjectManagedService, ID: service, RunID: privateRun, RunNumber: uint64(privateNumber)}
	default:
		return CertificateSubject{}, ErrCertificateIssuanceInvalid
	}
	if !subject.Valid() {
		return CertificateSubject{}, ErrCertificateIssuanceInvalid
	}
	return subject, nil
}

// CertificateSubject checks compatibility fields against the subject loaded from
// storage. callers constructing legacy work get the same exclusive validation.
func (w ACMEOrderWork) CertificateSubject() (CertificateSubject, error) {
	if w.PublishRunNumber > math.MaxInt64 || w.PrivateRunNumber > math.MaxInt64 {
		return CertificateSubject{}, ErrCertificateIssuanceInvalid
	}
	subject, err := certificateSubject(w.PublicURLID, w.PublishRunID, int64(w.PublishRunNumber), w.PrivateServiceID, w.PrivateRunID, int64(w.PrivateRunNumber))
	if err != nil || w.Subject != (CertificateSubject{}) && w.Subject != subject {
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
