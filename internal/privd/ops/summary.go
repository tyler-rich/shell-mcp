//go:build linux

package ops

// summaryData is priv_policy's result (handoff P-8). Stub: S4c-9 fills it
// in.
type summaryData struct {
	PolicySHA256 string
	Commands     []summaryCommand
	Ops          []summaryOp
}

type summaryCommand struct {
	ID             string
	Tier           string
	Unit           string
	Description    string
	Templates      [][]string
	RootEquivalent bool
	Capabilities   []string
}

type summaryOp struct {
	Op   string
	Tier string
	Unit string
}

// summary builds the privileged policy summary. Stub.
func (s *server) summary() summaryData { return summaryData{} }
