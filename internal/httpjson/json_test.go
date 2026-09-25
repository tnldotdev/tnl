package httpjson

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadAll(t *testing.T) {
	for _, test := range []struct {
		body     string
		limit    int64
		tooLarge bool
	}{
		{"", 0, false}, {"x", 0, true}, {"1234", 4, false}, {"12345", 4, true},
	} {
		body, err := ReadAll(strings.NewReader(test.body), test.limit)
		if errors.Is(err, ErrTooLarge) != test.tooLarge || (!test.tooLarge && (err != nil || string(body) != test.body)) {
			t.Fatalf("ReadAll(%q, %d) = %q, %v", test.body, test.limit, body, err)
		}
	}
	failure := errors.New("read failed")
	if _, err := ReadAll(iotest.ErrReader(failure), 4); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestDecode(t *testing.T) {
	for _, test := range []struct {
		body            string
		valid, trailing bool
		want            int
	}{
		{`{"value":1}`, true, false, 1}, {"{\"value\":1} \n", true, false, 1},
		{`null`, true, false, 0}, {`{"value":1,"value":2}`, true, false, 2},
		{`{"unknown":1}`, false, false, 0}, {`{`, false, false, 0}, {``, false, false, 0},
		{`{"value":1} {}`, false, true, 0}, {`{"value":1} garbage`, false, true, 0},
	} {
		var value struct {
			Value int `json:"value"`
		}
		err := Decode(json.NewDecoder(strings.NewReader(test.body)), &value)
		if (err == nil) != test.valid || errors.Is(err, ErrTrailingContent) != test.trailing {
			t.Errorf("Decode(%q) = %v", test.body, err)
		}
		if test.valid && value.Value != test.want {
			t.Errorf("Decode(%q) value = %d, want %d", test.body, value.Value, test.want)
		}
	}
	for _, useNumber := range []bool{false, true} {
		decoder := json.NewDecoder(strings.NewReader(`{"value":9007199254740993}`))
		if useNumber {
			decoder.UseNumber()
		}
		var value struct {
			Value any `json:"value"`
		}
		if err := Decode(decoder, &value); err != nil {
			t.Fatal(err)
		}
		if number, ok := value.Value.(json.Number); ok != useNumber || (ok && number.String() != "9007199254740993") {
			t.Fatalf("number = %#v", value.Value)
		}
		if !useNumber && value.Value != float64(9007199254740992) {
			t.Fatalf("rounded float64 = %#v", value.Value)
		}
	}
}

func TestDecodeRejectsTrailingContentBeyondRequestLimit(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`+strings.Repeat(" ", 20)+`{}`))
	request.Body = http.MaxBytesReader(httptest.NewRecorder(), request.Body, 10)
	var value struct{}
	if err := Decode(json.NewDecoder(request.Body), &value); !errors.Is(err, ErrTrailingContent) {
		t.Fatal(err)
	}
}

func TestWrite(t *testing.T) {
	response := httptest.NewRecorder()
	Write(response, http.StatusCreated, map[string]int{"value": 1})
	if response.Code != http.StatusCreated || response.Header().Get("Content-Type") != "application/json" || response.Body.String() != "{\"value\":1}\n" {
		t.Fatalf("response = %#v", response)
	}
	problem := httptest.NewRecorder()
	WriteProblem(problem, http.StatusBadRequest, map[string]string{"title": "invalid request"})
	if problem.Code != http.StatusBadRequest || problem.Header().Get("Content-Type") != "application/problem+json" || problem.Body.String() != "{\"title\":\"invalid request\"}\n" {
		t.Fatalf("problem response = %#v", problem)
	}
	for _, writer := range []http.ResponseWriter{httptest.NewRecorder(), failingWriter{httptest.NewRecorder()}} {
		func() {
			defer func() {
				if got := recover(); got != http.ErrAbortHandler {
					t.Errorf("panic = %v", got)
				}
			}()
			if _, ok := writer.(failingWriter); ok {
				Write(writer, 200, struct{}{})
			} else {
				Write(writer, 200, make(chan int))
			}
		}()
	}
}

type failingWriter struct{ http.ResponseWriter }

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
