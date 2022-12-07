package sanitizers

import (
	_ "runtime"
	"unsafe"
)

/*
#include <stdlib.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void __sanitizer_weak_hook_strstr(uintptr_t caller_pc, const char *s1,
                                 const char *s2, const char *result);
#ifdef __cplusplus
}
#endif
*/
import "C"

// runtime.libfuzzerHookStrCmp is the function used by Go when instrumenting string comparisons
// in libFuzzer mode. However, this function is internal in the runtime package and cannot
// be accessed directly. This is why we resort to the go:linkname trick in order to make it
// available to the hooks under the GuideTowardsEquality alias.

//go:linkname GuideTowardsEquality runtime.libfuzzerHookStrCmp
func GuideTowardsEquality(s1, s2 string, fakePC int)

/*
GuideTowardsContainment instructs the libFuzzer to guide its mutations towards making
haystack contain needle as a substring. fakePC serves as an ID to identify the call sites
of this function.

If the relation between the raw fuzzer input and the value of haystack is relatively
complex, running the fuzzer with the argument `-use_value_profile=1` may be necessary to
satisfy the substring check.
*/
func GuideTowardsContainment(haystack, needle string, fakePC int) {
	haystackCStr := C.CString(haystack)
	needleCStr := C.CString(needle)
	C.__sanitizer_weak_hook_strstr(C.uintptr_t(fakePC), haystackCStr, needleCStr, needleCStr)
	C.free(unsafe.Pointer(haystackCStr))
	C.free(unsafe.Pointer(needleCStr))
}
