package initial

import (
	"context"
	"database/sql"
	"fmt"
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
		_, err = conn.ExecContext(ctx, `UPDATE balances SET balance = balance + 10 WHERE user_id = ?;`, id)
	case 2:
		_, err = conn.PrepareContext(ctx, `UPDATE balances SET balance = balance + 10 WHERE user_id = ?;`)
	case 3:
		_, err = conn.QueryContext(ctx, `UPDATE balances SET balance = balance + 10 WHERE user_id = ?;`, id)
	default:
		row := conn.QueryRowContext(ctx, `UPDATE balances SET balance = balance + 10 WHERE user_id = ?;`, id)
		err = row.Err()
	}
	return
}

func updateBalanceExec(userID int, withContext bool) {
	var result sql.Result
	var err error
	if withContext {
		result, err = db.ExecContext(ctx, "UPDATE balances SET balance = balance + 10 WHERE user_id = ?", userID)
	} else {
		result, err = db.Exec("UPDATE balances SET balance = balance + 10 WHERE user_id = ?", userID)
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
		stmt, err = db.PrepareContext(ctx, "INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	} else {
		stmt, err = db.Prepare("INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	}
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close() // Prepared statements take up server resources and should be closed after use.

	for id, project := range projects {
		if withContext {
			_, err = stmt.ExecContext(ctx, id+1, project.mascot, project.release, "open source")
		} else {
			_, err = stmt.Exec(id+1, project.mascot, project.release, "open source")
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
		stmt, err = tx.PrepareContext(ctx, "INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	} else {
		stmt, err = tx.Prepare("INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	}
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close() // Prepared statements take up server resources and should be closed after use.

	for id, project := range projects {
		if withContext {
			_, err = stmt.ExecContext(ctx, id+1, project.mascot, project.release, "open source")
		} else {
			_, err = stmt.Exec(id+1, project.mascot, project.release, "open source")
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

	stmt, err := db.Prepare("INSERT INTO projects(id, mascot, release, category) VALUES( ?, ?, ?, ? )")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close() // Prepared statements take up server resources and should be closed after use.

	for id, project := range projects {
		if withContext {
			_, err = stmt.QueryContext(ctx, id+1, project.mascot, project.release, "open source")
		} else {
			_, err = stmt.Query(id+1, project.mascot, project.release, "open source")
		}
		if err != nil {
			log.Fatal(err)
		}
	}
}

func getVersion() string {
	var version string

	err := db.QueryRow("SELECT VERSION()").Scan(&version)
	if err != nil {
		log.Fatal(err)
	}

	return version
}

func getUsersOlderThan(age int, withContext bool) {
	var rows *sql.Rows
	var err error
	if withContext {
		rows, err = db.QueryContext(ctx, "SELECT name FROM users WHERE age=?", age)
	} else {
		rows, err = db.Query("SELECT name FROM users WHERE age=?", age)
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
		_, err = tx.ExecContext(ctx, `UPDATE users SET status = ? WHERE id = ?`, "paid", id)
	} else {
		_, err = tx.Exec(`UPDATE users SET status = ? WHERE id = ?`, "paid", id)
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
		_, err = tx.QueryContext(ctx, `UPDATE users SET status = ? WHERE id = ?`, "paid", id)
	} else {
		_, err = tx.Query(`UPDATE users SET status = ? WHERE id = ?`, "paid", id)
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
		err = db.QueryRowContext(ctx, "SELECT username, created_at FROM users WHERE id=?", id).Scan(&username, &created)
	} else {
		err = db.QueryRow("SELECT username, created_at FROM users WHERE id=?", id).Scan(&username, &created)
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
		err = tx.QueryRowContext(ctx, "SELECT username, created_at FROM users WHERE id=?", id).Scan(&username, &created)
	} else {
		err = tx.QueryRow("SELECT username, created_at FROM users WHERE id=?", id).Scan(&username, &created)
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
