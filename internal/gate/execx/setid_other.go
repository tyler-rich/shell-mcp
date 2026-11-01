//go:build linux && !(amd64 || arm64)

package execx

import "errors"

// setIDs refuses: the credential option is built for D-018's architectures,
// amd64 and arm64, whose set*id system calls take the 32-bit ids directly.
func setIDs(*Credential) (string, error) {
	return "setgroups", errors.New("the credential option is built for amd64 and arm64 only")
}
