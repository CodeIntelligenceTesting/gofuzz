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

type SQLInjection struct {
	DetectorClass
}

func (si *SQLInjection) Detect() *SQLInjection {
	if isSyntaxError(si.err) {
		si.detect = true
	}
	if si.cmd != "" {
		fuzzer.GuideTowardsContainment(si.cmd, SQLCharactersToEscape, si.id)
	}
	return si
}

func (si *SQLInjection) Report(args ...any) {
	if !si.detect {
		return
	}
	if errors.Is(si.err, SQLInjectionError) {
		if len(si.cmd) > 0 {
			reporter.ReportFindingf("%s: query %s, args [%s]", si.err.Error(), si.cmd, fmt.Sprint(args...))
		} else {
			reporter.ReportFindingf("%s: args [%s]", si.err.Error(), fmt.Sprint(args...))
		}
	}
}

func NewSQLInjection(id int, query string, err error) *SQLInjection {
	return &SQLInjection{
		DetectorClass: DetectorClass{
			id:     id,
			detect: false,
			cmd:    query,
			tree:   nil,
			err:    err,
		},
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
