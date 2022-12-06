package sanitizers

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
)

// Characters that should be escaped in user input.
// See https://dev.mysql.com/doc/refman/8.0/en/string-literals.html
const charactersToEscape = "'\"\b\n\r\t\\%_"

var syntaxErrors = []*regexp.Regexp{
	regexp.MustCompile(`\S+ ERROR 1064 \(42000\): You have an error in your SQL syntax.*`), // MySQL error message
	regexp.MustCompile(`\S+ ERROR: syntax error at or near .* \(SQLSTATE 42601\)`),         // PostgreSQL error message
}

func ConnExecContext(hookId int, conn *sql.Conn, ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, err := conn.ExecContext(ctx, query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return result, err
}

func ConnPrepareContext(hookId int, conn *sql.Conn, ctx context.Context, query string) (*sql.Stmt, error) {
	GuideTowardsContainment(query, charactersToEscape, hookId)
	return conn.PrepareContext(ctx, query)
}

func ConnQueryContext(hookId int, conn *sql.Conn, ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, err := conn.QueryContext(ctx, query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return rows, err
}

func ConnQueryRowContext(hookId int, conn *sql.Conn, ctx context.Context, query string, args ...any) *sql.Row {
	row := conn.QueryRowContext(ctx, query, args...)
	if isSyntaxError(row.Err()) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return row
}

func DbExec(hookId int, db *sql.DB, query string, args ...any) (sql.Result, error) {
	result, err := db.Exec(query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return result, err
}

func DbExecContext(hookId int, db *sql.DB, ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, err := db.ExecContext(ctx, query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return result, err
}

func DbQuery(hookId int, db *sql.DB, query string, args ...any) (*sql.Rows, error) {
	rows, err := db.Query(query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return rows, err
}

func DbQueryContext(hookId int, db *sql.DB, ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return rows, err
}

func DbQueryRow(hookId int, db *sql.DB, query string, args ...any) *sql.Row {
	row := db.QueryRow(query, args...)
	if isSyntaxError(row.Err()) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return row
}

func DbQueryRowContext(hookId int, db *sql.DB, ctx context.Context, query string, args ...any) *sql.Row {
	row := db.QueryRowContext(ctx, query, args...)
	if isSyntaxError(row.Err()) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return row
}

func DbPrepare(hookId int, db *sql.DB, query string) (*sql.Stmt, error) {
	GuideTowardsContainment(query, charactersToEscape, hookId)
	return db.Prepare(query)
}

func DbPrepareContext(hookId int, db *sql.DB, ctx context.Context, query string) (*sql.Stmt, error) {
	GuideTowardsContainment(query, charactersToEscape, hookId)
	return db.PrepareContext(ctx, query)
}

func TxExec(hookId int, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	result, err := tx.Exec(query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return result, err
}

func TxExecContext(hookId int, tx *sql.Tx, ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, err := tx.ExecContext(ctx, query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return result, err
}

func TxQuery(hookId int, tx *sql.Tx, query string, args ...any) (*sql.Rows, error) {
	rows, err := tx.Query(query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return rows, err
}

func TxQueryContext(hookId int, tx *sql.Tx, ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return rows, err
}

func TxQueryRow(hookId int, tx *sql.Tx, query string, args ...any) *sql.Row {
	row := tx.QueryRow(query, args...)
	if isSyntaxError(row.Err()) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return row
}

func TxQueryRowContext(hookId int, tx *sql.Tx, ctx context.Context, query string, args ...any) *sql.Row {
	row := tx.QueryRowContext(ctx, query, args...)
	if isSyntaxError(row.Err()) {
		ReportFindingf("SQL Injection: query %s, args %s", query, fmt.Sprint(args))
	} else {
		GuideTowardsContainment(query, charactersToEscape, hookId)
	}
	return row
}

func TxPrepare(hookId int, tx *sql.Tx, query string) (*sql.Stmt, error) {
	GuideTowardsContainment(query, charactersToEscape, hookId)
	return tx.Prepare(query)
}

func TxPrepareContext(hookId int, tx *sql.Tx, ctx context.Context, query string) (*sql.Stmt, error) {
	GuideTowardsContainment(query, charactersToEscape, hookId)
	return tx.PrepareContext(ctx, query)
}

func StmtExec(_ int, stmt *sql.Stmt, args ...any) (sql.Result, error) {
	result, err := stmt.Exec(args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: args %s", fmt.Sprint(args))
	}
	return result, err
}

func StmtExecContext(_ int, stmt *sql.Stmt, ctx context.Context, args ...any) (sql.Result, error) {
	result, err := stmt.ExecContext(ctx, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: args %s", fmt.Sprint(args))
	}
	return result, err
}

func StmtQuery(_ int, stmt *sql.Stmt, args ...any) (*sql.Rows, error) {
	rows, err := stmt.Query(args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: args %s", fmt.Sprint(args))
	}
	return rows, err
}

func StmtQueryContext(_ int, stmt *sql.Stmt, ctx context.Context, args ...any) (*sql.Rows, error) {
	rows, err := stmt.QueryContext(ctx, args...)
	if isSyntaxError(err) {
		ReportFindingf("SQL Injection: args %s", fmt.Sprint(args))
	}
	return rows, err
}

func StmtQueryRow(_ int, stmt *sql.Stmt, args ...any) *sql.Row {
	row := stmt.QueryRow(args...)
	if isSyntaxError(row.Err()) {
		ReportFindingf("SQL Injection: args %s", fmt.Sprint(args))
	}
	return row
}

func StmtQueryRowContext(_ int, stmt *sql.Stmt, ctx context.Context, args ...any) *sql.Row {
	row := stmt.QueryRowContext(ctx, args...)
	if isSyntaxError(row.Err()) {
		ReportFindingf("SQL Injection: args %s", fmt.Sprint(args))
	}
	return row
}

func isSyntaxError(err error) bool {
	for _, pattern := range syntaxErrors {
		if pattern.MatchString(err.Error()) {
			return true
		}
	}
	return false
}
