package webauth

/*
SQL Database Driver
*/

import "database/sql"
import "log"
import "github.com/rhomel/webauth/util"
import "errors"
import "runtime/debug"

func init() {
	log.SetFlags(log.Lshortfile)
}

const SqlCreateTablePg = `CREATE TABLE users (userid SERIAL PRIMARY KEY, username VARCHAR(256), email VARCHAR(256), password CHAR(60), resettoken VARCHAR(64), tokenexpiration DATE, locked BOOLEAN, failedattempts INTEGER, type VARCHAR(100))`

const SqlCreateTableSqlite = `CREATE TABLE users (userid INTEGER PRIMARY KEY autoincrement, username VARCHAR(256), email VARCHAR(256), password CHAR(60), resettoken VARCHAR(64), tokenexpiration DATE, locked INTEGER, failedattempts INTEGER, type VARCHAR(100))`

var ExecutingTransactions int

const Commit = "Commit"
const Rollback = "Rollback"

func EndTx(tx *sql.Tx, call string) error {
	ExecutingTransactions--
	var err error
	switch call {
	case Commit:
		err = tx.Commit()
	default:
		err = tx.Rollback()
	}

	if err != nil {
		util.DPrintf("WARNING: %v returned an error", call)
	}

	return err
}

func BeginTx(db *sql.DB) (*sql.Tx, error) {
	ExecutingTransactions++
	return db.Begin()
}

/*
SQL Database Driver
*/
type DriverSql struct {
	initialized bool
	dbtype      string
	db          *sql.DB
	opener      func() (*sql.DB, error)
}

func NewDriverSql(dbtype string, db *sql.DB) *DriverSql {
	if db == nil {
		log.Fatal("A null database handle was given to driver_sql.go:NewDriverSql()")
	}
	driver := DriverSql{false, dbtype, db, nil}
	return &driver
}

func NewDriverSqlNoConnectionCache(dbtype string, opener func() (*sql.DB, error)) *DriverSql {
	if opener == nil {
		log.Fatal("A null database opener method was given to driver_sql.go:NewDriverSqlNoConnectionCache()")
	}
	driver := DriverSql{false, dbtype, nil, opener}
	return &driver
}

/*
Open the database if in non-persistent database connection mode.

If an operation needs to *write* to the database, it should call OpenDb
and defer a CloseDb to guarantee the connection is freed.

If an operation will *only read* from the database, it can just call OpenDb
without CloseDb since no blocking locks will be acquired.

OpenDb can safely be called multiple times since it checks to see if
the database is already connected first before attempting to create a
new connection.
*/
func (d *DriverSql) OpenDb() {
	if d.opener == nil {
		// in persistent connection mode, no need to re-open
		return
	}
	if d.db != nil {
		// database aleady open
		return
	}

	util.DPrintln("SQL Opening a new db connection")

	var err error
	d.db, err = d.opener()
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
}

// Close the database if in non-persistent database connection mode.
func (d *DriverSql) CloseDb() {
	if d.opener != nil {
		util.DPrintln("SQL Closing db connection")
		d.db.Close()
		d.db = nil
	}
}

func (d *DriverSql) Initialize() error {
	d.OpenDb()
	defer d.CloseDb()

	util.DPrintln("SQL Select")
	rows, err := d.db.Query("SELECT COUNT(*) FROM users")
	if rows != nil {
		rows.Close()
	}

	if err != nil {
		// table most likely doesn't exist, create it
		var sqlCreate string

		switch d.dbtype {
		case "postgres":
			sqlCreate = SqlCreateTablePg
		case "sqlite3":
			sqlCreate = SqlCreateTableSqlite
		default:
			err := errors.New("Unsupported Database type: " + d.dbtype)
			log.Fatal(err)
			return err
		}

		_, err := d.db.Exec(sqlCreate)
		if err != nil {
			// something went wrong with the database
			log.Fatal(err)
			return err
		}
	}

	// query succeeded, no need to create the table
	d.initialized = true
	return nil
}

func (d *DriverSql) IsInitialized() bool {
	return d.initialized
}

// insert
func (d *DriverSql) NewInternalAuthRecord(user string, email string, password string) (AuthInternalRecord, error, bool) {
	d.OpenDb()
	defer d.CloseDb()

	var err error

	tx, err := BeginTx(d.db)
	util.DPrintf("SQL Start Transaction")
	if err != nil {
		util.DPrintf("Executing transaction count: %v\n", ExecutingTransactions)
		debug.PrintStack()
		log.Fatal(err)
		return nil, err, false
	}

	//defer EndTx(tx, Rollback)

	var rows *sql.Rows

	// verify email doesn't exist
	util.DPrintln("SQL Select")
	rows, err = tx.Query("SELECT COUNT(*) FROM users WHERE type='internal' and email = $1", email)
	if err != nil {
		log.Fatal(err)
		return nil, err, false
	}

	if rows.Next() {
		var count int
		rows.Scan(&count)

		if count > 0 {
			// account already exists
			return nil, nil, false
		}
	}

	rows.Close()

	// verify user doesn't exist
	util.DPrintln("SQL Select")
	rows, err = tx.Query("SELECT COUNT(*) FROM users WHERE type='internal' and username = $1", user)
	if err != nil {
		log.Fatal(err)
		return nil, err, false
	}

	if rows.Next() {
		var count int
		rows.Scan(&count)

		if count > 0 {
			// row already exists
			return nil, nil, false
		}
	}

	rows.Close()

	// insert
	util.DPrintln("SQL Insert")
	stmt, err := tx.Prepare("INSERT INTO users (username, email, password, resettoken, tokenexpiration, locked, failedattempts, type) VALUES ($1, $2, $3, $4, $5, $6, $7, 'internal')")
	if err != nil {
		log.Fatal(err)
		return nil, err, false
	}

	record := NewBasicInternalAuthRecord(user, email)
	util.DPrintln(record.String())
	record.SetPassword(password)

	var tokenExpiration interface{}

	if d.dbtype == "sqlite3" {
		// sqlite doesn't have a date type
		tokenExpiration = record.GetTokenExpirationIso()
	} else {
		tokenExpiration = record.GetTokenExpiration()
	}

	_, err = stmt.Exec(record.User, record.Email, record.Password, record.ResetToken, tokenExpiration, record.Locked, record.FailedAttempts)
	stmt.Close()

	if err != nil {
		log.Fatal(err)
		return nil, err, false
	}

	if err := EndTx(tx, Commit); err != nil {
		log.Fatalf("Error attempting to commit transaction: %v", err)
	}

	util.DPrintf("SQL End Transaction")

	// do this to get the userid generated by the database
	returnRecord, _ := d.getInternalAuthRecord(record.User)

	return returnRecord, nil, true
}

func (d *DriverSql) GetInternalAuthRecord(user string) (AuthInternalRecord, error) {
	d.OpenDb()
	defer d.CloseDb()
	return d.getInternalAuthRecord(user)
}

func (d *DriverSql) getInternalAuthRecord(user string) (AuthInternalRecord, error) {
	util.DPrintln("SQL Select")
	rows, err := d.db.Query("SELECT userid, username, email, password, resettoken, tokenexpiration, locked, failedattempts FROM users WHERE type='internal' and username = $1", user)
	defer rows.Close()
	if err != nil {
		log.Fatal(err)
	}

	if !rows.Next() {
		return nil, nil
	}

	record := d.newRecord(rows)

	return record, nil
}

func (d *DriverSql) GetInternalAuthRecordByEmail(email string) (AuthInternalRecord, error) {
	d.OpenDb()
	defer d.CloseDb()
	return d.getInternalAuthRecordByEmail(email)
}

func (d *DriverSql) getInternalAuthRecordByEmail(email string) (AuthInternalRecord, error) {
	util.DPrintln("SQL Select")
	rows, err := d.db.Query("SELECT userid, username, email, password, resettoken, tokenexpiration, locked, failedattempts FROM users WHERE type='internal' and email = $1", email)
	defer rows.Close()
	if err != nil {
		log.Fatal(err)
	}

	if !rows.Next() {
		return nil, nil
	}

	record := d.newRecord(rows)

	return record, nil
}

func (d *DriverSql) newRecord(rows *sql.Rows) *BasicInternalAuthRecord {
	record := BasicInternalAuthRecord{}

	var err error
	if d.dbtype == "sqlite3" {
		var stime string
		err = rows.Scan(&record.UserId, &record.User, &record.Email, &record.Password, &record.ResetToken, &stime, &record.Locked, &record.FailedAttempts)
		record.SetTokenExpirationIso([]byte(stime))
	} else {
		err = rows.Scan(&record.UserId, &record.User, &record.Email, &record.Password, &record.ResetToken, &record.TokenExpiration, &record.Locked, &record.FailedAttempts)
	}

	if err != nil {
		log.Fatal(err)
	}

	return &record
}

// update
func (d *DriverSql) UpdateInternalAuthRecord(record AuthInternalRecord) error {
	d.OpenDb()
	defer d.CloseDb()

	var tx *sql.Tx
	var err error
	var rows *sql.Rows

	tx, err = BeginTx(d.db)
	util.DPrintf("SQL Start Transaction")
	if err != nil {
		log.Fatal(err)
		_ = EndTx(tx, Rollback)
		return err
	}

	//defer EndTx(tx, Rollback)

	// need to make sure there is no conflict with new username and new email
	util.DPrintln("SQL Select")
	rows, err = d.db.Query("SELECT COUNT(*) FROM users WHERE type='internal' and email = $1 and userid <> $2", record.GetEmail(), record.GetUserId())
	if err != nil {
		log.Fatal(err)
		return err
	}

	if rows.Next() {
		var count int
		rows.Scan(&count)

		if count > 0 {
			// account already exists
			return errors.New("email already registered")
		}
	}

	rows.Close()

	util.DPrintln("SQL Select")
	rows, err = d.db.Query("SELECT COUNT(*) FROM users WHERE type='internal' and user = $1 and userid <> $2", record.GetUser(), record.GetUserId())
	if err != nil {
		log.Fatal(err)
		return err
	}

	if rows.Next() {
		var count int
		rows.Scan(&count)

		if count > 0 {
			// account already exists
			return errors.New("username already registered")
		}
	}

	rows.Close()

	// ok to update
	util.DPrintln("SQL Update")
	stmt, err := tx.Prepare("UPDATE users SET username = $1, email = $2, password = $3, resettoken = $4, tokenexpiration = $5, locked = $6, failedattempts = $7 WHERE type='internal' AND userid = $8")
	if err != nil {
		log.Fatal(err)
		_ = EndTx(tx, Rollback)
		return err
	}

	_, err = stmt.Exec(record.GetUser(), record.GetEmail(), record.GetEncryptedPassword(), record.GetResetToken(), record.GetTokenExpirationIso(), record.IsLocked(), record.GetFailedAttempts(), record.GetUserId())
	stmt.Close()

	if err != nil {
		log.Fatal(err)
		return err
	}

	if err := EndTx(tx, Commit); err != nil {
		log.Fatalf("Error attempting to commit transaction: %v", err)
	}

	util.DPrintf("SQL End Transaction")

	return nil
}
