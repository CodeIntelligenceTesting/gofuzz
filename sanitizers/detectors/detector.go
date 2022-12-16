package detectors

import (
	"text/template/parse"
)

type DetectorClass struct {
	id     int         // numeric identifier to distinguish between the detectors for the various call sites
	detect bool        // Is toggled on when a bug was detected
	cmd    string      // the tampered with SQL query/cmd/path/...
	tree   *parse.Tree // Template injection specific field
	err    error       // Generic error handler
}

// Detector defines the interface for the bug detectors.
type Detector interface {
	// Detect performs checks to detect specific classes of bugs and returns specialized errors
	// representing the found bugs. The function can also guide the fuzzer towards producing
	// interesting inputs that trigger the bugs of interest.
	Detect() *DetectorClass
}
