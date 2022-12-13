package detectors

import (
	"errors"
	"regexp"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
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
	id    int    // numeric identifier to distinguish between the detectors for the various call sites
	query string // the SQL query that has been executed
	err   error  // the error resulting from executing the SQL query
}

// Make sure that the SQL injection detector implements the Detector interface
var _ Detector = (*SQLInjection)(nil)

func (si *SQLInjection) Detect() error {
	if isSyntaxError(si.err) {
		return SQLInjectionError
	}
	if si.query != "" {
		fuzzer.GuideTowardsContainment(si.query, SQLCharactersToEscape, si.id)
	}
	return nil
}

func NewSQLInjection(id int, query string, err error) *SQLInjection {
	return &SQLInjection{
		id:    id,
		query: query,
		err:   err,
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
