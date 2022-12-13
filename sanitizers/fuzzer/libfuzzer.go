package fuzzer

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

void __sanitizer_weak_hook_strcmp(uintptr_t called_pc, const char *s1,
                                  const char *s2, int result);

void __sanitizer_weak_hook_strstr(uintptr_t caller_pc, const char *s1,
                                 const char *s2, const char *result);
#ifdef __cplusplus
}
#endif
*/
import "C"

// Starting from Go 1.19 the runtime package has a function runtime.libfuzzerHookStrCmp
// that calls __sanitizer_weak_hook_strcmp. We can make this internal function available
// here using the go:linkname trick. We opted to use cgo to call this function to make sure
// that the sanitizers module also work for code bases using older Go versions.

/*
GuideTowardsEquality instructs the libFuzzer to guide its mutations towards making current
equal to target. fakePC serves as an ID to identify the call sites of this function.

If the relation between the raw fuzzer input and the value of current is relatively
complex, running the fuzzer with the argument `-use_value_profile=1` may be necessary to
achieve equality.
*/
func GuideTowardsEquality(s1, s2 string, fakePC int) {
	s1CStr := C.CString(s1)
	s2CStr := C.CString(s2)
	C.__sanitizer_weak_hook_strcmp(C.uintptr_t(fakePC), s1CStr, s2CStr, C.int(1))
	C.free(unsafe.Pointer(s1CStr))
	C.free(unsafe.Pointer(s2CStr))
}

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
