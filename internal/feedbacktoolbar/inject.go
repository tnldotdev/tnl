package feedbacktoolbar

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

const maximumHTMLPrefix = 8192

// Inject adds the versioned toolbar script to eligible development HTML while
// forwarding the remaining body as it arrives from the local service.
func Inject(response *http.Response) error {
	if response == nil || response.Request == nil || response.Request.Method != http.MethodGet ||
		response.StatusCode != http.StatusOK || response.Body == nil ||
		response.Header.Get("Content-Disposition") != "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "text/html" {
		return nil
	}
	encoding := strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		return nil
	}
	if strings.Contains(strings.ToLower(strings.Join(response.Header.Values("Content-Security-Policy"), ";")), "sandbox") &&
		!strings.Contains(strings.ToLower(strings.Join(response.Header.Values("Content-Security-Policy"), ";")), "allow-scripts") {
		return nil
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("generate feedback script nonce: %w", err)
	}
	nonce := base64.RawStdEncoding.EncodeToString(random)
	_, path := Script()
	tag := []byte(`<script type="module" nonce="` + nonce + `" src="` + path + `"></script>`)
	addToolbarNonce(response.Header, nonce)
	response.Header.Del("Content-Length")
	response.Header.Del("ETag")
	response.Header.Del("Content-MD5")
	response.Header.Del("Last-Modified")
	response.Header.Del("Accept-Ranges")
	response.Header.Set("Cache-Control", "no-store")
	response.ContentLength = -1
	response.TransferEncoding = nil
	upstream := response.Body
	reader, writer := io.Pipe()
	response.Body = &toolbarBody{PipeReader: reader, upstream: upstream}
	go func() {
		writer.CloseWithError(streamHTMLWithToolbar(writer, upstream, tag))
		_ = upstream.Close()
	}()
	return nil
}

type toolbarBody struct {
	*io.PipeReader
	upstream io.ReadCloser
}

func (b *toolbarBody) Close() error {
	return errors.Join(b.PipeReader.Close(), b.upstream.Close())
}

func streamHTMLWithToolbar(output io.Writer, input io.Reader, tag []byte) error {
	reader := bufio.NewReader(input)
	prefix := make([]byte, 0, maximumHTMLPrefix)
	for len(prefix) < maximumHTMLPrefix {
		character, err := reader.ReadByte()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			if _, err := output.Write(prefix); err != nil {
				return err
			}
			_, err = output.Write(tag)
			return err
		}
		prefix = append(prefix, character)
		if after := headTagEnd(prefix); after > 0 {
			if _, err := output.Write(prefix[:after]); err != nil {
				return err
			}
			if _, err := output.Write(tag); err != nil {
				return err
			}
			if _, err := output.Write(prefix[after:]); err != nil {
				return err
			}
			_, err := io.Copy(output, reader)
			return err
		}
	}
	if _, err := output.Write(prefix); err != nil {
		return err
	}
	if _, err := io.Copy(output, reader); err != nil {
		return err
	}
	_, err := output.Write(tag)
	return err
}

func headTagEnd(prefix []byte) int {
	lower := bytes.ToLower(prefix)
	for start := 0; start < len(lower); start++ {
		if !bytes.HasPrefix(lower[start:], []byte("<head")) || start+5 >= len(lower) {
			continue
		}
		boundary := lower[start+5]
		if boundary != '>' && boundary != ' ' && boundary != '\t' && boundary != '\n' {
			continue
		}
		quote := byte(0)
		for index := start + 5; index < len(lower); index++ {
			character := lower[index]
			if quote != 0 {
				if character == quote {
					quote = 0
				}
			} else if character == '\'' || character == '"' {
				quote = character
			} else if character == '>' {
				return index + 1
			}
		}
	}
	return 0
}

func addToolbarNonce(headers http.Header, nonce string) {
	for _, field := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		values := headers.Values(field)
		if len(values) == 0 {
			continue
		}
		headers.Del(field)
		for _, policy := range values {
			parts := strings.Split(policy, ";")
			foundScript, foundStyle := false, false
			defaultSources := ""
			for _, part := range parts {
				trimmed := strings.TrimSpace(part)
				fields := strings.Fields(trimmed)
				if len(fields) == 0 {
					continue
				}
				if fields[0] == "default-src" {
					defaultSources = strings.TrimSpace(strings.TrimPrefix(trimmed, "default-src "))
				}
				if fields[0] == "script-src" {
					foundScript = true
				}
				if fields[0] == "style-src" {
					foundStyle = true
				}
			}
			for index, part := range parts {
				trimmed := strings.TrimSpace(part)
				fields := strings.Fields(trimmed)
				if len(fields) != 0 && (fields[0] == "script-src-elem" || fields[0] == "script-src" || fields[0] == "style-src-elem" || fields[0] == "style-src") {
					parts[index] = part + " 'nonce-" + nonce + "'"
				}
			}
			if !foundScript {
				parts = append(parts, "script-src "+defaultSources+" 'nonce-"+nonce+"'")
			}
			if !foundStyle {
				parts = append(parts, "style-src "+defaultSources+" 'nonce-"+nonce+"'")
			}
			headers.Add(field, strings.Join(parts, ";"))
		}
	}
}
