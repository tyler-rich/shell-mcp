// Package certs inspects the certificates in a file for the gate's
// cert_inspect op (docs/ARCHITECTURE.md §4.3), natively with crypto/x509.
package certs

import (
	"errors"
	"time"
)

// MaxCertificates bounds how many certificates one file may hold.
const MaxCertificates = 256

// Errors. None carries file content.
var (
	ErrPrivateKey     = errors.New("file contains a private key")
	ErrNoCertificates = errors.New("file contains no certificates")
	ErrTooMany        = errors.New("file contains too many certificates")
)

// Cert describes one certificate.
type Cert struct {
	Index              int      `json:"index"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialHex          string   `json:"serial_hex"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	EmailAddresses     []string `json:"email_addresses"`
	URIs               []string `json:"uris"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	DaysRemaining      int      `json:"days_remaining"`
	Expired            bool     `json:"expired"`
	NotYetValid        bool     `json:"not_yet_valid"`
	KeyType            string   `json:"key_type"`
	KeyBits            int      `json:"key_bits"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	IsCA               bool     `json:"is_ca"`
	SelfSigned         bool     `json:"self_signed"`
	SHA256             string   `json:"sha256"`
}

// Result is what Inspect found.
type Result struct {
	Format       string `json:"format"`
	Certificates []Cert `json:"certificates"`
	Unparsable   int    `json:"unparsable"`
}

// Inspect is not implemented yet.
func Inspect(_ []byte, _ time.Time) (Result, error) { return Result{}, ErrNoCertificates }
