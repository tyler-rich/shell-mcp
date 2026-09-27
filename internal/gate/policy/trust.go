package policy

import "errors"

// Trust is the set of uids trusted to own the policy, its directories, the
// gate binary and command binaries. In production it is exactly {0}. It can
// only be widened through TrustForTesting, which nothing outside test code
// may call (enforced by TestForTestingOnlyInTests); there is no flag,
// environment variable or request field that reaches it.
type Trust struct {
	uids []uint32
}

// RootTrust trusts uid 0 only.
func RootTrust() Trust { return Trust{uids: []uint32{0}} }

// TrustForTesting trusts uid 0 and uid, so tests can own their fixtures.
func TrustForTesting(uid uint32) Trust { return Trust{uids: []uint32{0, uid}} }

// Owns reports whether uid is trusted.
func (t Trust) Owns(uid uint32) bool {
	for _, u := range t.uids {
		if u == uid {
			return true
		}
	}
	return false
}

// OwnershipError reports a file or directory that is not owned by a trusted
// uid, is group/other-writable, or has the wrong type.
type OwnershipError struct {
	Path   string
	Reason string
}

func (e *OwnershipError) Error() string { return e.Path + ": " + e.Reason }

// CheckChain verifies that p (after resolving symlinks) and every parent
// directory up to "/" are owned by a trusted uid and not group/other-
// writable; symlink components of the path as written must also be owned by
// a trusted uid. It returns the resolved path.
func CheckChain(t Trust, p string) (string, error) {
	return "", errors.New("not implemented")
}
