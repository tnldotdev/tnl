package clientstate

type secretProtector interface {
	Seal(string, []byte) ([]byte, error)
	Open(string, []byte) ([]byte, error)
}
