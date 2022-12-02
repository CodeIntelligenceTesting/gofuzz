package sanitizers

import (
	_ "runtime"
	_ "unsafe"
)

// runtime.libfuzzerHookStrCmp is the function used by Go when instrumenting string comparisons
// in libFuzzer mode. However, this function is internal in the runtime package and cannot
// be accessed directly. This is why we resort to the go:linkname trick in order to make it
// available to the hooks under the GuideTowardsEquality alias.

//go:linkname GuideTowardsEquality runtime.libfuzzerHookStrCmp
func GuideTowardsEquality(s1, s2 string, fakePC int)
