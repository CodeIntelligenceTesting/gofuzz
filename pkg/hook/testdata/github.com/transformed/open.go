package initial

import (
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
)

// Here we have a single use of the os package, and the associated call is replaced by a call
// to the corresponding hook in the sanitizers package. This results in an unused that should
// be removed by the transformer.
func openArbitraryFile(name string) {
	if _, err := goSanitizers.OsOpen(0, name); err != nil {
		panic(err)
	}
}
