package protocol

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestPublicationSelectionCannotPrintItsCredential(t *testing.T) {
	const token = "tnc_private-test-key"
	var request Invocation
	if err := json.Unmarshal([]byte(`{"version":1,"invocation_id":"ivk_0123456789ABCDEFGHIJKL","owner":"0123456789abcdef0123456789abcdef","pid":1,"target":"http://127.0.0.1:3000","deployment":{"project":"acme/shop","name":"production","credential":"`+token+`"}}`), &request); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%s %v %+v %#v", request, request, request, request), token) {
		t.Fatal("publication credential appeared in printable request")
	}
	encoded, err := json.Marshal(request)
	if err != nil || !strings.Contains(string(encoded), token) {
		t.Fatal("private IPC request lost its credential", err)
	}
}
