package credentials

import "errors"

// AssignmentSeed derives managed publisher connection credentials. its stored
// encoding is unchanged, but it never authorizes public URL run operations.
type AssignmentSeed string

var ErrInvalidAssignmentSeed = errors.New("invalid assignment seed")

func (s AssignmentSeed) String() string { return string(s) }

func NewAssignmentSeed() (AssignmentSeed, error) {
	seed, _, _, err := newToken(sessionPrefix)
	return AssignmentSeed(seed), err
}

func ParseAssignmentSeed(seed AssignmentSeed) error {
	_, _, err := parseToken(seed.String(), sessionPrefix, ErrInvalidAssignmentSeed)
	return err
}

func DeriveAssignmentCredential(seed AssignmentSeed, assignmentContext string) (PublisherConnectionCredential, SecretHash, error) {
	if err := ParseAssignmentSeed(seed); err != nil || assignmentContext == "" {
		return "", SecretHash{}, ErrInvalidAssignmentSeed
	}
	return deriveConnectionCredential(validatedTokenSecret(seed.String(), sessionPrefix), assignmentContext)
}
