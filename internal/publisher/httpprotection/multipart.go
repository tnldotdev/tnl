package httpprotection

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func init() {
	plugins.RegisterBodyProcessor("tnl_multipart", func() plugintypes.BodyProcessor { return memoryMultipart{} })
}

// memoryMultipart exposes form fields and file metadata to CRS without retaining
// a second copy of uploaded files. the enclosing transaction already bounds and
// buffers the original body in memory for unchanged forwarding.
type memoryMultipart struct{}

var dispositionParameters = regexp.MustCompile(`(?:^|;)\s*([^=;\s]+)\s*=`)

func (memoryMultipart) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	kind, parameters, err := mime.ParseMediaType(options.Mime)
	if err != nil || kind != "multipart/form-data" || parameters["boundary"] == "" {
		return errors.New("invalid multipart content type")
	}
	form := multipart.NewReader(reader, parameters["boundary"])
	var total int64
	fields := 0
	for {
		part, err := form.NextRawPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("invalid multipart boundary")
		}
		for name, values := range part.Header {
			if len(values) != 1 || strings.EqualFold(name, "Content-Transfer-Encoding") {
				return errors.New("ambiguous multipart header")
			}
		}
		disposition := part.Header.Get("Content-Disposition")
		kind, parameters, err := mime.ParseMediaType(disposition)
		if err != nil || kind != "form-data" || parameters["name"] == "" {
			return errors.New("invalid multipart disposition")
		}
		// reject extended/continued filenames and repeated parameters instead of
		// choosing one of the interpretations different backends may accept.
		seen := make(map[string]bool)
		for _, match := range dispositionParameters.FindAllStringSubmatch(disposition, -1) {
			name := strings.ToLower(match[1])
			if name != "name" && name != "filename" || seen[name] {
				return errors.New("ambiguous multipart disposition")
			}
			seen[name] = true
		}
		for name := range parameters {
			if !seen[name] {
				return errors.New("unsupported multipart disposition")
			}
		}
		name := parameters["name"]
		v.MultipartName().Add(name, name)
		for key, values := range part.Header {
			v.MultipartPartHeaders().Add(name, key+": "+values[0])
		}
		filename := parameters["filename"]
		var size int64
		if filename != "" {
			size, err = io.Copy(io.Discard, part)
			v.MultipartFilename().Add(name, filename)
			v.Files().Add("", filename)
			v.FilesNames().Add("", name)
			v.FilesSizes().Add(filename, fmt.Sprint(size))
		} else {
			fields++
			if options.ArgumentLimit > 0 && fields > options.ArgumentLimit {
				return errors.New("too many multipart fields")
			}
			var value []byte
			value, err = io.ReadAll(part)
			size = int64(len(value))
			v.ArgsPost().Add(name, string(value))
		}
		if err != nil {
			return errors.New("truncated multipart part")
		}
		total += size
		// Coraza's plugin interface exposes reads on single collections; the
		// concrete transaction supplies the same setter used by its processors.
		v.FilesCombinedSize().(interface{ Set(string) }).Set(fmt.Sprint(total))
	}
}

func (memoryMultipart) ProcessResponse(io.Reader, plugintypes.TransactionVariables, plugintypes.BodyProcessorOptions) error {
	return errors.New("multipart response inspection is disabled")
}
