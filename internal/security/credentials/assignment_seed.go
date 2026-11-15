package credentials

import "errors"

const assignmentSeedPrefix = "tnl_assignment_seed_"

// AssignmentSeed derives publisher connection credentials, not service run tokens.
type AssignmentSeed string

var ErrInvalidAssignmentSeed = errors.New("invalid assignment seed")

func (s AssignmentSeed) String() string { return string(s) }

func NewAssignmentSeed() (AssignmentSeed, error) {
	seed, _, _, err := newToken(assignmentSeedPrefix)
	return AssignmentSeed(seed), err
}

func ParseAssignmentSeed(seed AssignmentSeed) error {
	_, _, err := parseToken(seed.String(), assignmentSeedPrefix, ErrInvalidAssignmentSeed)
	return err
}

func DeriveAssignmentCredential(seed AssignmentSeed, assignmentContext string) (PublisherConnectionCredential, SecretHash, error) {
	if err := ParseAssignmentSeed(seed); err != nil || assignmentContext == "" {
		return "", SecretHash{}, ErrInvalidAssignmentSeed
	}
	return deriveConnectionCredential(validatedTokenSecret(seed.String(), assignmentSeedPrefix), assignmentContext)
}
