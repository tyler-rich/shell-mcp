//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"errors"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/certs"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

type certData struct {
	Path string `json:"path"`
	certs.Result
}

// certInspect parses every certificate in a file under the read roots. The
// file's bytes are never returned; a file holding a private key is refused.
func (s *server) certInspect(raw jsontext.Value) (data any, warns []string, failure error) {
	var a pathArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if a.Path == "" {
		return nil, nil, errf(protocol.CodeBadRequest, "path is required")
	}
	b, err := s.fs.ReadRaw(a.Path, s.p.Limits.MaxReadBytes)
	if err != nil {
		return nil, nil, err
	}
	res, err := certs.Inspect(b, time.Now())
	switch {
	case errors.Is(err, certs.ErrPrivateKey):
		return nil, nil, errf(protocol.CodePathDenied, "file contains a private key")
	case errors.Is(err, certs.ErrTooMany):
		return nil, nil, errf(protocol.CodeTooLarge, "file contains more than %d certificates", certs.MaxCertificates)
	case err != nil:
		return nil, nil, errf(protocol.CodeBadRequest, "file contains no parsable certificates")
	}
	var warnings []string
	if res.Unparsable > 0 {
		warnings = append(warnings, "some certificate blocks could not be parsed")
	}
	return certData{Path: a.Path, Result: res}, warnings, nil
}
