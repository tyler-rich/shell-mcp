// Package certs inspects the certificates in a file for the gate's
// cert_inspect op (docs/ARCHITECTURE.md §4.3), natively with crypto/x509.
//
// A file that contains a private key anywhere — a PEM block of any
// "… PRIVATE KEY" type, or DER that parses as a PKCS#8, PKCS#1 or SEC 1
// private key — is refused before any certificate is parsed, and nothing
// from it is returned. Errors never carry file content.
package certs

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// Bounds.
const (
	// MaxCertificates bounds how many certificates one file may hold.
	MaxCertificates = 256
	// MaxNames bounds each SAN list of one certificate.
	MaxNames = 256
)

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
	NamesTruncated     bool     `json:"names_truncated"`
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

// Result is what Inspect found. Unparsable counts PEM certificate blocks
// that did not parse.
type Result struct {
	Format       string `json:"format"`
	Certificates []Cert `json:"certificates"`
	Unparsable   int    `json:"unparsable"`
}

// certTypes are the PEM block types parsed as certificates.
var certTypes = []string{"CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"}

// ContainsPrivateKey reports whether data holds a private key: a PEM
// private-key header anywhere (the shared redaction rule), a decodable PEM
// block of any private-key type, or DER that parses as a private key.
func ContainsPrivateKey(data []byte) bool {
	if redact.ContainsPrivateKey(data) {
		return true
	}
	rest := data
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		if strings.Contains(strings.ToUpper(b.Type), "PRIVATE KEY") {
			return true
		}
		rest = r
	}
	return derKey(data)
}

func derKey(data []byte) bool {
	if _, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return true
	}
	_, err := x509.ParseECPrivateKey(data)
	return err == nil
}

// Inspect parses every PEM or DER certificate in data. now decides expiry
// and days remaining.
func Inspect(data []byte, now time.Time) (Result, error) {
	if ContainsPrivateKey(data) {
		return Result{}, ErrPrivateKey
	}
	res := Result{Certificates: []Cert{}}
	var parsed []*x509.Certificate
	rest, sawPEM := data, false
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		rest, sawPEM = r, true
		isCert := false
		for _, t := range certTypes {
			isCert = isCert || b.Type == t
		}
		if !isCert {
			continue
		}
		if len(parsed) == MaxCertificates {
			return Result{}, ErrTooMany
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			res.Unparsable++
			continue
		}
		parsed = append(parsed, c)
	}
	res.Format = "pem"
	if !sawPEM {
		res.Format = "der"
		cs, err := x509.ParseCertificates(data)
		if err != nil {
			return Result{}, ErrNoCertificates
		}
		if len(cs) > MaxCertificates {
			return Result{}, ErrTooMany
		}
		parsed = cs
	}
	if len(parsed) == 0 {
		return Result{}, ErrNoCertificates
	}
	for i, c := range parsed {
		res.Certificates = append(res.Certificates, describe(i, c, now))
	}
	return res, nil
}

func capNames(in []string, truncated *bool) []string {
	if len(in) > MaxNames {
		*truncated = true
		in = in[:MaxNames]
	}
	if in == nil {
		return []string{}
	}
	return in
}

func describe(i int, c *x509.Certificate, now time.Time) Cert {
	sum := sha256.Sum256(c.Raw)
	serial := "00"
	if c.SerialNumber != nil && c.SerialNumber.Sign() != 0 {
		serial = hex.EncodeToString(c.SerialNumber.Bytes())
	}
	d := Cert{
		Index: i, Subject: c.Subject.String(), Issuer: c.Issuer.String(), SerialHex: serial,
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining:      int(math.Floor(c.NotAfter.Sub(now).Hours() / 24)),
		Expired:            now.After(c.NotAfter),
		NotYetValid:        now.Before(c.NotBefore),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:               c.BasicConstraintsValid && c.IsCA,
		SHA256:             hex.EncodeToString(sum[:]),
	}
	d.DNSNames = capNames(c.DNSNames, &d.NamesTruncated)
	ips := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}
	d.IPAddresses = capNames(ips, &d.NamesTruncated)
	d.EmailAddresses = capNames(c.EmailAddresses, &d.NamesTruncated)
	uris := make([]string, 0, len(c.URIs))
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}
	d.URIs = capNames(uris, &d.NamesTruncated)
	d.KeyType, d.KeyBits = keyInfo(c)
	d.SelfSigned = bytes.Equal(c.RawSubject, c.RawIssuer) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
	return d
}

func keyInfo(c *x509.Certificate) (keyType string, bits int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		if k.Curve == nil {
			return "ECDSA", 0
		}
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	case *ecdh.PublicKey:
		return "X25519", 256
	}
	return c.PublicKeyAlgorithm.String(), 0
}
