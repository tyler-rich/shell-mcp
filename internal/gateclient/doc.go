// Package gateclient is the client side of the gate protocol (ARCHITECTURE
// §4): one session per request, exec of the gate hello, one bounded request
// (≤ 2 MiB, lowercase UUID v4 id) and one bounded, strictly decoded response
// (≤ 4 MiB), within the tool's time budget. Transport failures map to the
// server codes of ARCHITECTURE §6; gate codes pass through unchanged.
package gateclient
