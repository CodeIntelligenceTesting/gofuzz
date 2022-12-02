package initial

import (
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
)

func PrintPlain(data []byte) {
	goSanitizers.
		FakePrintln(0, string(data))
}
