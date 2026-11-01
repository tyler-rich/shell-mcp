package setup

import (
	"errors"

	"net/netip"
)

// MaxFrom bounds a from= list.
const MaxFrom = 8

// The from= floors (handoff §7 Q1): no IPv4 prefix shorter than /24, no
// IPv6 prefix shorter than /64, an IPv4-mapped IPv6 prefix judged as the
// IPv4 prefix it maps. A hard limit: no flag, variable or file lowers them.
const (
	minIPv4Bits = 24
	minIPv6Bits = 64
)

// mappedRange is ::ffff:0:0/96, where IPv4-mapped addresses live.
var mappedRange = netip.MustParsePrefix("::ffff:0:0/96")

// ErrFrom is a refused from= entry.
var ErrFrom = errors.New("from= refused")

// FromEntry is one accepted from= entry: the prefix it covers and the text
// written into the key line (canonical: an address as an address, a prefix
// as a prefix).
type FromEntry struct {
	Prefix netip.Prefix
	Text   string
}

// FromList is the key line's from= value.
func FromList(es []FromEntry) string { var stub0 string; return stub0 }

// ParseFrom checks a from= list (TARGET-SETUP §12.1): each entry an IP
// address or a canonical CIDR prefix (host bits refused), no host name,
// wildcard or negation, no duplicate, at most MaxFrom entries, and none
// wider than the floors. It returns the entries and a WARN for each entry
// wider than one address.
func ParseFrom(list []string) ([]FromEntry, []string, error) {
	var stub0 []FromEntry
	var stub1 []string
	var stub2 error
	return stub0, stub1, stub2
}

func parseFromEntry(s string) (FromEntry, error) {
	var stub0 FromEntry
	var stub1 error
	return stub0, stub1
}

// IPv4-mapped: judged as the IPv4 prefix it maps, so ::ffff:0:0/96
// (all of IPv4) and anything containing it are refused.
