package reporter

import (
	"fmt"
)

func ReportFindingf(format string, args ...any) {
	ReportFinding(fmt.Sprintf(format, args...))
}

func ReportFinding(args ...any) {
	panic(fmt.Sprintf("GolangSanitizer: %s", fmt.Sprint(args...)))
}
