package detectors

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

// SQLCharactersToEscape represents the characters that should be escaped in user input.
// See https://dev.mysql.com/doc/refman/8.0/en/string-literals.html
const SQLCharactersToEscape = "'\"\b\n\r\t\\%_"

var SQLInjectionError = errors.New("SQL injection error")

var syntaxErrors = []*regexp.Regexp{
	regexp.MustCompile(`\S+ ERROR 1064 \(42000\): You have an error in your SQL syntax.*`), // MySQL error message
	regexp.MustCompile(`\S+ ERROR: syntax error at or near .* \(SQLSTATE 42601\)`),         // PostgreSQL error message
}

func (dc *DetectorClass) DetectSQLI() *DetectorClass {
	if isSyntaxError(dc.err) {
		dc.detect = true
	}
	if dc.cmd != "" {
		fuzzer.GuideTowardsContainment(dc.cmd, SQLCharactersToEscape, dc.id)
	}
	return dc

}

func (dc *DetectorClass) ReportSQLI(args ...any) {
	if !dc.detect {
		return
	}
	if errors.Is(dc.err, SQLInjectionError) {
		if len(dc.cmd) > 0 {
			reporter.ReportFindingf("%s: query %s, args [%s]", dc.err.Error(), dc.cmd, fmt.Sprint(args...))
		} else {
			reporter.ReportFindingf("%s: args [%s]", dc.err.Error(), fmt.Sprint(args...))
		}
	}
}

func isSyntaxError(err error) bool {
	for _, pattern := range syntaxErrors {
		if pattern.MatchString(err.Error()) {
			return true
		}
	}
	return false
}
