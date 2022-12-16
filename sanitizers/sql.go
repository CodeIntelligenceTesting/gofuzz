package sanitizers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
)

func reportOnDetectionSQLI(hookId int, query string, sqlErr error, args ...any) {
	err := detectors.NewSQLInjection(hookId, query, sqlErr).Detect()
	if errors.Is(err, detectors.SQLInjectionError) {
		if len(query) > 0 {
			ReportFindingf("%s: query %s, args [%s]", err.Error(), query, fmt.Sprint(args...))
		} else {
			ReportFindingf("%s: args [%s]", err.Error(), fmt.Sprint(args...))
		}
	}

}

func ConnExecContext(hookId int, conn *sql.Conn, ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, sqlErr := conn.ExecContext(ctx, query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return result, sqlErr
}

func ConnPrepareContext(hookId int, conn *sql.Conn, ctx context.Context, query string) (*sql.Stmt, error) {
	fuzzer.GuideTowardsContainment(query, detectors.SQLCharactersToEscape, hookId)
	return conn.PrepareContext(ctx, query)
}

func ConnQueryContext(hookId int, conn *sql.Conn, ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, sqlErr := conn.QueryContext(ctx, query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return rows, sqlErr
}

func ConnQueryRowContext(hookId int, conn *sql.Conn, ctx context.Context, query string, args ...any) *sql.Row {
	row := conn.QueryRowContext(ctx, query, args...)
	reportOnDetectionSQLI(hookId, query, row.Err(), args...)
	return row
}

func DbExec(hookId int, db *sql.DB, query string, args ...any) (sql.Result, error) {
	result, sqlErr := db.Exec(query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return result, sqlErr
}

func DbExecContext(hookId int, db *sql.DB, ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, sqlErr := db.ExecContext(ctx, query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return result, sqlErr
}

func DbQuery(hookId int, db *sql.DB, query string, args ...any) (*sql.Rows, error) {
	rows, sqlErr := db.Query(query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return rows, sqlErr
}

func DbQueryContext(hookId int, db *sql.DB, ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, sqlErr := db.QueryContext(ctx, query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return rows, sqlErr
}

func DbQueryRow(hookId int, db *sql.DB, query string, args ...any) *sql.Row {
	row := db.QueryRow(query, args...)
	reportOnDetectionSQLI(hookId, query, row.Err(), args...)
	return row
}

func DbQueryRowContext(hookId int, db *sql.DB, ctx context.Context, query string, args ...any) *sql.Row {
	row := db.QueryRowContext(ctx, query, args...)
	reportOnDetectionSQLI(hookId, query, row.Err(), args...)
	return row
}

func DbPrepare(hookId int, db *sql.DB, query string) (*sql.Stmt, error) {
	fuzzer.GuideTowardsContainment(query, detectors.SQLCharactersToEscape, hookId)
	return db.Prepare(query)
}

func DbPrepareContext(hookId int, db *sql.DB, ctx context.Context, query string) (*sql.Stmt, error) {
	fuzzer.GuideTowardsContainment(query, detectors.SQLCharactersToEscape, hookId)
	return db.PrepareContext(ctx, query)
}

func TxExec(hookId int, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	result, sqlErr := tx.Exec(query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return result, sqlErr
}

func TxExecContext(hookId int, tx *sql.Tx, ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, sqlErr := tx.ExecContext(ctx, query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return result, sqlErr
}

func TxQuery(hookId int, tx *sql.Tx, query string, args ...any) (*sql.Rows, error) {
	rows, sqlErr := tx.Query(query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return rows, sqlErr
}

func TxQueryContext(hookId int, tx *sql.Tx, ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, sqlErr := tx.QueryContext(ctx, query, args...)
	reportOnDetectionSQLI(hookId, query, sqlErr, args...)
	return rows, sqlErr
}

func TxQueryRow(hookId int, tx *sql.Tx, query string, args ...any) *sql.Row {
	row := tx.QueryRow(query, args...)
	reportOnDetectionSQLI(hookId, query, row.Err(), args...)
	return row
}

func TxQueryRowContext(hookId int, tx *sql.Tx, ctx context.Context, query string, args ...any) *sql.Row {
	row := tx.QueryRowContext(ctx, query, args...)
	reportOnDetectionSQLI(hookId, query, row.Err(), args...)
	return row
}

func TxPrepare(hookId int, tx *sql.Tx, query string) (*sql.Stmt, error) {
	fuzzer.GuideTowardsContainment(query, detectors.SQLCharactersToEscape, hookId)
	return tx.Prepare(query)
}

func TxPrepareContext(hookId int, tx *sql.Tx, ctx context.Context, query string) (*sql.Stmt, error) {
	fuzzer.GuideTowardsContainment(query, detectors.SQLCharactersToEscape, hookId)
	return tx.PrepareContext(ctx, query)
}

func StmtExec(_ int, stmt *sql.Stmt, args ...any) (sql.Result, error) {
	result, sqlErr := stmt.Exec(args...)
	reportOnDetectionSQLI(0, "", sqlErr, args...)
	return result, sqlErr
}

func StmtExecContext(_ int, stmt *sql.Stmt, ctx context.Context, args ...any) (sql.Result, error) {
	result, sqlErr := stmt.ExecContext(ctx, args...)
	reportOnDetectionSQLI(0, "", sqlErr, args...)
	return result, sqlErr
}

func StmtQuery(_ int, stmt *sql.Stmt, args ...any) (*sql.Rows, error) {
	rows, sqlErr := stmt.Query(args...)
	reportOnDetectionSQLI(0, "", sqlErr, args...)
	return rows, sqlErr
}

func StmtQueryContext(_ int, stmt *sql.Stmt, ctx context.Context, args ...any) (*sql.Rows, error) {
	rows, sqlErr := stmt.QueryContext(ctx, args...)
	reportOnDetectionSQLI(0, "", sqlErr, args...)
	return rows, sqlErr
}

func StmtQueryRow(_ int, stmt *sql.Stmt, args ...any) *sql.Row {
	row := stmt.QueryRow(args...)
	reportOnDetectionSQLI(0, "", row.Err(), args...)
	return row
}

func StmtQueryRowContext(_ int, stmt *sql.Stmt, ctx context.Context, args ...any) *sql.Row {
	row := stmt.QueryRowContext(ctx, args...)
	reportOnDetectionSQLI(0, "", row.Err(), args...)
	return row
}
