package initial

import (
	"fmt"
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
)

func PrintFormatted(format string, data []byte) {
	if format == "" {
		goSanitizers.
			FakePrintln(920984872, string(data))
	} else {
		fmt.Printf(format, string(data))
	}
}
