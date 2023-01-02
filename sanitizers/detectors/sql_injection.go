package detectors

import (
	"fmt"
	"regexp"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

// SQLCharactersToEscape represents the characters that should be escaped in user input.
// See https://dev.mysql.com/doc/refman/8.0/en/string-literals.html
const SQLCharactersToEscape = "'\"\b\n\r\t\\%_"

var syntaxErrors = []*regexp.Regexp{
	regexp.MustCompile(`\S+ ERROR 1064 \(42000\): You have an error in your SQL syntax.*`), // MySQL error message
	regexp.MustCompile(`\S+ ERROR: syntax error at or near .* \(SQLSTATE 42601\)`),         // PostgreSQL error message
}

var _ Detector = (*SQLInjection)(nil)

type SQLInjection struct {
	id    int    // Numeric identifier to distinguish between the detectors for the various call sites
	query string // SQL query that has been executed
	err   error  // Error if `query` caused any unintended behavior
	vargs []any  // Supplemental arguments that allow a more verbose error reporting
}

func (sqli *SQLInjection) Detect() {
	if isSyntaxError(sqli.err) {
		if len(sqli.query) > 0 {
			reporter.ReportFindingf("SQL Injection: query %s, args [%s]", sqli.query, fmt.Sprint(sqli.vargs...))
		} else {
			reporter.ReportFindingf("SQL Injection: args [%s]", fmt.Sprint(sqli.vargs...))
		}
	}
	if sqli.query != "" {
		fuzzer.GuideTowardsContainment(sqli.query, SQLCharactersToEscape, sqli.id)
	}
}

func NewSQLInjection(id int, query string, err error, vargs ...any) *SQLInjection {
	return &SQLInjection{id, query, err, vargs}
}

func isSyntaxError(err error) bool {
	for _, pattern := range syntaxErrors {
		if pattern.MatchString(err.Error()) {
			return true
		}
	}
	return false
}
