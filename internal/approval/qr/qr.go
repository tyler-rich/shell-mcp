// Package qr encodes a QR Code (ISO/IEC 18004) for the enrolment command:
// byte mode, error-correction level M, versions 1-10, the mask chosen from
// all eight by the standard penalty scoring.
package qr

import "errors"

// MaxBytes is the most a version 10-M symbol holds in byte mode.
const MaxBytes = 213

// QuietZone is the light border, in modules, that rendering adds.
const QuietZone = 4

// ErrTooLong is returned for data longer than MaxBytes.
var ErrTooLong = errors.New("qr: data longer than a version 10-M symbol holds")

// Code is an encoded symbol.
type Code struct {
	version, mask, size int
	modules             []bool
}

// Encode encodes data in the smallest version that holds it.
func Encode([]byte) (*Code, error) { return nil, errors.New("qr: not implemented") }

func encode([]byte, int) (*Code, error) { return nil, errors.New("qr: not implemented") }

// Version returns the symbol's version.
func (*Code) Version() int { return 0 }

// Mask returns the mask pattern used.
func (*Code) Mask() int { return 0 }

// Size returns the width and height in modules.
func (*Code) Size() int { return 0 }

// Dark reports whether the module at column x, row y is dark.
func (*Code) Dark(int, int) bool { return false }

// Terminal renders the symbol for a terminal.
func (*Code) Terminal() string { return "" }
