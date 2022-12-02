package initial

import (
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
)

func PrintPlain(data []byte) {
	goSanitizers.
		FakePrintln(3757165058, string(data))
}
