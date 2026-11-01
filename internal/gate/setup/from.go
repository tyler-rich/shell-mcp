package setup

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
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
func FromList(es []FromEntry) string {
	t := make([]string, len(es))
	for i, e := range es {
		t[i] = e.Text
	}
	return strings.Join(t, ",")
}

// ParseFrom checks a from= list (TARGET-SETUP §12.1): each entry an IP
// address or a canonical CIDR prefix (host bits refused), no host name,
// wildcard or negation, no duplicate, at most MaxFrom entries, and none
// wider than the floors. It returns the entries and a WARN for each entry
// wider than one address.
func ParseFrom(list []string) ([]FromEntry, []string, error) {
	if len(list) == 0 {
		return nil, nil, fmt.Errorf("%w: the from= list is empty; give the server's own address", ErrFrom)
	}
	if len(list) > MaxFrom {
		return nil, nil, fmt.Errorf("%w: %d entries, at most %d", ErrFrom, len(list), MaxFrom)
	}
	var out []FromEntry
	var warns []string
	seen := map[netip.Prefix]bool{}
	for _, s := range list {
		e, err := parseFromEntry(s)
		if err != nil {
			return nil, nil, err
		}
		if seen[e.Prefix] {
			return nil, nil, fmt.Errorf("%w: %q is listed twice", ErrFrom, s)
		}
		seen[e.Prefix] = true
		if e.Prefix.Bits() < e.Prefix.Addr().BitLen() {
			one := "/32"
			if e.Prefix.Addr().Is6() {
				one = "/128"
			}
			warns = append(warns, fmt.Sprintf("from= entry %s covers more than one address; the server's own fixed address alone (%s) is narrower", e.Text, one))
		}
		out = append(out, e)
	}
	return out, warns, nil
}

func parseFromEntry(s string) (FromEntry, error) {
	switch {
	case s == "":
		return FromEntry{}, fmt.Errorf("%w: an empty entry", ErrFrom)
	case strings.ContainsAny(s, "*?"):
		return FromEntry{}, fmt.Errorf("%w: %q is a wildcard; give addresses or prefixes", ErrFrom, s)
	case strings.HasPrefix(s, "!"):
		return FromEntry{}, fmt.Errorf("%w: %q is a negation; give addresses or prefixes", ErrFrom, s)
	}
	var e FromEntry
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return FromEntry{}, fmt.Errorf("%w: %q has a zone", ErrFrom, s)
		}
		e = FromEntry{Prefix: netip.PrefixFrom(a, a.BitLen()), Text: a.String()}
	} else if p, err := netip.ParsePrefix(s); err == nil {
		if p.Masked() != p {
			return FromEntry{}, fmt.Errorf("%w: %q has host bits set; the prefix is %s", ErrFrom, s, p.Masked())
		}
		e = FromEntry{Prefix: p, Text: p.String()}
	} else {
		return FromEntry{}, fmt.Errorf("%w: %q is not an IP address or a CIDR prefix (host names are refused: they make sshd consult DNS)", ErrFrom, s)
	}
	p := e.Prefix
	if p.Addr().IsUnspecified() && p.Bits() == p.Addr().BitLen() {
		return FromEntry{}, fmt.Errorf("%w: %q is the unspecified address", ErrFrom, s)
	}
	switch {
	case p.Addr().Is4():
		if p.Bits() < minIPv4Bits {
			return FromEntry{}, fmt.Errorf("%w: %q is wider than /%d, the floor for IPv4 (no override)", ErrFrom, s, minIPv4Bits)
		}
	case p.Overlaps(mappedRange):
		// IPv4-mapped: judged as the IPv4 prefix it maps, so ::ffff:0:0/96
		// (all of IPv4) and anything containing it are refused.
		if p.Bits() < mappedRange.Bits() || p.Bits()-mappedRange.Bits() < minIPv4Bits {
			return FromEntry{}, fmt.Errorf("%w: %q maps an IPv4 prefix wider than /%d, the floor for IPv4 (no override)", ErrFrom, s, minIPv4Bits)
		}
	default:
		if p.Bits() < minIPv6Bits {
			return FromEntry{}, fmt.Errorf("%w: %q is wider than /%d, the floor for IPv6 (no override)", ErrFrom, s, minIPv6Bits)
		}
	}
	return e, nil
}
