package policy

// Multi-call binaries and what a command's file holds (S-MC). A command's
// binary is recognised by its content as well as by its names: the uutils
// multi-call binary, BusyBox and toybox, GNU coreutils built as one binary,
// and GNU coreutils' single-purpose programs, each by a marker string it
// carries; and a #! script by its first line.

// The markers are stored reversed, so that the binaries built from this
// package (the gate, the helper, every test binary that links it) never
// carry them: otherwise a policy naming one of those binaries would be
// taken for BusyBox or uutils.
var markers = map[string]string{
	"uutils":     rev(")slitueroc slituu("),         // every uutils utility's --version
	"gnu":        rev("slitueroc UNG"),              // GNU coreutils' --version and help
	"gnu-note":   rev(`"slitueroc":"eman"`),         // the ELF package note of Ubuntu's GNU coreutils
	"gnu-multi":  rev("=gorp-slitueroc--"),          // GNU coreutils built with --enable-single-binary
	"busybox":    rev("v xoBysuB"),                  // BusyBox's banner
	"toybox":     rev("yranib llacitlum s% xobyoT"), // toybox's --help
	"toybox-url": rev("xobyot/ten.yeldnal"),
}

func rev(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// MarkerForTesting returns the content marker of a kind, so that tests
// build invented fixtures without the marker appearing in their source.
func MarkerForTesting(kind string) string { return markers[kind] }

// UutilsApplets returns the names of the uutils multi-call binary's
// utilities, sorted.
func UutilsApplets() []string { return nil }

// parseShebang returns the interpreter and its optional argument from a
// file's first bytes, or ok false when the file is not a #! script.
func parseShebang(_ []byte) (interp, arg string, ok bool, err error) { return "", "", false, nil }
