package initial

import (
	"context"
	"database/sql"
	"fmt"
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
	"log"
	"strings"
	"time"
)

var (
	ctx context.Context
	db  *sql.DB
)

func callConnMethods(mid int) (err error) {
	// A *DB is a pool of connections. Call Conn to reserve a connection for
	// exclusive use.
	conn, err := db.Conn(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close() // Return the connection to the pool.
	id := 1
	switch mid {
	case 1:
		_, err = goSanitizers.ConnExecContext(0, conn, ctx, `UPDATE balances SET balance = balance + 10 WHERE user_id = ?;`, id)
	case 2:
		_, err = goSanitizers.ConnPrepareContext(0, conn, ctx, `UPDATE balances SET balance = balance + 10 WHERE user_id = ?;`)
	case 3:
		_, err = goSanitizers.ConnQueryContext(0, conn, ctx, `UPDATE balances SET balance = balance + 10 WHERE user_id = ?;`, id)
	default:
		row := goSanitizers.ConnQueryRowContext(0, conn, ctx, `UPDATE balances SET balance = balance + 10 WHERE user_id = ?;`, id)
		err = row.Err()
	}
	return
}

func updateBalanceExec(userID int, withContext bool) {
	var result sql.Result
	var err error
	if withContext {
		result, err = goSanitizers.DbExecContext(0, db, ctx, "UPDATE balances SET balance = balance + 10 WHERE user_id = ?", userID)
	} else {
		result, err = goSanitizers.DbExec(0, db, "UPDATE balances SET balance = balance + 10 WHERE user_id = ?", userID)
	}

	if err != nil {
		log.Fatal(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		log.Fatal(err)
	}
	if rows != 1 {
		log.Fatalf("expected to affect 1 row, affected %d", rows)
	}
}

func addProjectsExecDb(withContext bool) {
	projects := []struct {
		mascot  string
		release int
	}{
		{"tux", 1991},
		{"duke", 1996},
		{"gopher", 2009},
		{"moby dock", 2013},
	}

	var stmt *sql.Stmt
	var err error
	if withContext {
		stmt, err = goSanitizers.DbPrepareContext(0, db, ctx, "INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	} else {
		stmt, err = goSanitizers.DbPrepare(0, db, "INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	}
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close() // Prepared statements take up server resources and should be closed after use.

	for id, project := range projects {
		if withContext {
			_, err = goSanitizers.StmtExecContext(0, stmt, ctx, id+1, project.mascot, project.release, "open source")
		} else {
			_, err = goSanitizers.StmtExec(0, stmt, id+1, project.mascot, project.release, "open source")
		}
		if err != nil {
			log.Fatal(err)
		}
	}
}

func addProjectsExecTx(withContext bool) {
	projects := []struct {
		mascot  string
		release int
	}{
		{"tux", 1991},
		{"duke", 1996},
		{"gopher", 2009},
		{"moby dock", 2013},
	}

	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Rollback() // The rollback will be ignored if the tx has been committed later in the function.

	var stmt *sql.Stmt
	if withContext {
		stmt, err = goSanitizers.TxPrepareContext(0, tx, ctx, "INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	} else {
		stmt, err = goSanitizers.TxPrepare(0, tx, "INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	}
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close() // Prepared statements take up server resources and should be closed after use.

	for id, project := range projects {
		if withContext {
			_, err = goSanitizers.StmtExecContext(0, stmt, ctx, id+1, project.mascot, project.release, "open source")
		} else {
			_, err = goSanitizers.StmtExec(0, stmt, id+1, project.mascot, project.release, "open source")
		}
		if err != nil {
			log.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
}

func addProjectsQuery(withContext bool) {
	projects := []struct {
		mascot  string
		release int
	}{
		{"tux", 1991},
		{"duke", 1996},
		{"gopher", 2009},
		{"moby dock", 2013},
	}

	stmt, err := goSanitizers.DbPrepare(0, db, "INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close() // Prepared statements take up server resources and should be closed after use.

	for id, project := range projects {
		if withContext {
			_, err = goSanitizers.StmtQueryContext(0, stmt, ctx, id+1, project.mascot, project.release, "open source")
		} else {
			_, err = goSanitizers.StmtQuery(0, stmt, id+1, project.mascot, project.release, "open source")
		}
		if err != nil {
			log.Fatal(err)
		}
	}
}

func getVersion() string {
	var version string

	err := goSanitizers.DbQueryRow(0, db, "SELECT VERSION()").Scan(&version)
	if err != nil {
		log.Fatal(err)
	}

	return version
}

func getUsersOlderThan(age int, withContext bool) {
	var rows *sql.Rows
	var err error
	if withContext {
		rows, err = goSanitizers.DbQueryContext(0, db, ctx, "SELECT name FROM users WHERE age=?", age)
	} else {
		rows, err = goSanitizers.DbQuery(0, db, "SELECT name FROM users WHERE age=?", age)
	}

	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	names := make([]string, 0)

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			// Check for a scan error.
			// Query rows will be closed with defer.
			log.Fatal(err)
		}
		names = append(names, name)
	}
	// If the database is being written to ensure to check for Close
	// errors that may be returned from the driver. The query may
	// encounter an auto-commit error and be forced to rollback changes.
	rerr := rows.Close()
	if rerr != nil {
		log.Fatal(rerr)
	}

	// Rows.Err will report the last error encountered by Rows.Scan.
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s are %d years old", strings.Join(names, ", "), age)
}

func updateUsersExec(status string, id int, withContext bool) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}

	if withContext {
		_, err = goSanitizers.TxExecContext(0, tx, ctx, `UPDATE users SET status = ? WHERE id = ?`, "paid", id)
	} else {
		_, err = goSanitizers.TxExec(0, tx, `UPDATE users SET status = ? WHERE id = ?`, "paid", id)
	}
	if err != nil {
		_ = tx.Rollback()
		log.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
}

func updateUsersQuery(status string, id int, withContext bool) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}

	if withContext {
		_, err = goSanitizers.TxQueryContext(0, tx, ctx, `UPDATE users SET status = ? WHERE id = ?`, "paid", id)
	} else {
		_, err = goSanitizers.TxQuery(0, tx, `UPDATE users SET status = ? WHERE id = ?`, "paid", id)
	}
	if err != nil {
		_ = tx.Rollback()
		log.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
}

func selectUserDb(id int, withContext bool) {
	var err error
	var username string
	var created time.Time
	if withContext {
		err = goSanitizers.DbQueryRowContext(0, db, ctx, "SELECT username, created_at FROM users WHERE id=?", id).Scan(&username, &created)
	} else {
		err = goSanitizers.DbQueryRow(0, db, "SELECT username, created_at FROM users WHERE id=?", id).Scan(&username, &created)
	}
	switch {
	case err == sql.ErrNoRows:
		log.Printf("no user with id %d\n", id)
	case err != nil:
		log.Fatalf("query error: %v\n", err)
	default:
		log.Printf("username is %q, account created on %s\n", username, created)
	}
}

func selectUserTx(id int, withContext bool) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}

	var username string
	var created time.Time
	if withContext {
		err = goSanitizers.TxQueryRowContext(0, tx, ctx, "SELECT username, created_at FROM users WHERE id=?", id).Scan(&username, &created)
	} else {
		err = goSanitizers.TxQueryRow(0, tx, "SELECT username, created_at FROM users WHERE id=?", id).Scan(&username, &created)
	}
	switch {
	case err == sql.ErrNoRows:
		log.Printf("no user with id %d\n", id)
	case err != nil:
		log.Fatalf("query error: %v\n", err)
	default:
		log.Printf("username is %q, account created on %s\n", username, created)
	}
}
