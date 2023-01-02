package detectors

type Detector interface {
	// `Detect` performs class-specific checks for various classes of bugs and upon discovering them report them to the user
	// followed by process termiantion. The function can also guide the fuzzer towards producing
	// interesting inputs that trigger the bugs of interest.
	Detect()
}
