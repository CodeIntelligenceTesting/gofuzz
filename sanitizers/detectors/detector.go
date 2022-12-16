package detectors

// Detector defines the interface for the bug detectors.
type Detector interface {
	// Detect performs checks to detect specific classes of bugs and returns specialized errors
	// representing the found bugs. The function can also guide the fuzzer towards producing
	// interesting inputs that trigger the bugs of interest.
	Detect() error
}
