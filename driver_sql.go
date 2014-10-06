package webauth

/*
SQL Database Driver
*/

import "database/sql"
import "log"
import "errors"

func init() {
    log.SetFlags(log.Llongfile)
}

const SqlCreateTablePg = `CREATE TABLE users (userid SERIAL PRIMARY KEY, username VARCHAR(256), email VARCHAR(256), password CHAR(60), resettoken VARCHAR(64), tokenexpiration DATE, locked INTEGER, failedattempts INTEGER, type VARCHAR(100))`

const SqlCreateTableSqlite = `CREATE TABLE users (userid INTEGER PRIMARY KEY autoincrement, username VARCHAR(256), email VARCHAR(256), password CHAR(60), resettoken VARCHAR(64), tokenexpiration DATE, locked INTEGER, failedattempts INTEGER, type VARCHAR(100))`

/*
SQL Database Driver
*/
type DriverSql struct {
    initialized bool
    dbtype string
    db *sql.DB
}

func NewDriverSql(dbtype string, db *sql.DB) *DriverSql {
    driver := DriverSql{false,dbtype,db}
    return &driver
}

func (d *DriverSql) Initialize() error {
    _, err := d.db.Query("SELECT COUNT(*) FROM users")

    if err != nil {
        // table most likely doesn't exist, create it
        var sqlCreate string

        switch d.dbtype {
        case "pg", "pgsql", "postgres", "postgresql":
            sqlCreate = SqlCreateTablePg
        case "sqlite", "sqlite3":
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
func (d *DriverSql) NewInternalAuthRecord(user string, email string, password string) (AuthInternalRecord, error, bool)  {

    var rows *sql.Rows
    var err error

    // verify email doesn't exist
    rows, err = d.db.Query("SELECT COUNT(*) FROM users WHERE type='internal' and email=?", email)
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
    rows, err = d.db.Query("SELECT COUNT(*) FROM users WHERE type='internal' and username=?", user)
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
    tx, err := d.db.Begin()
    if err != nil {
        log.Fatal(err)
        return nil, err, false
    }

    stmt, err := tx.Prepare("INSERT INTO users (userid, username, email, password, resettoken, tokenexpiration, locked, failedattempts, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'internal')")
    if err != nil {
        log.Fatal(err)
        return nil, err, false
    }

    record := NewBasicInternalAuthRecord(user, email)
    log.Println(record.String())
    record.SetPassword(password)

    _, err = stmt.Exec(record.UserId, record.User, record.Email, record.Password, record.ResetToken, record.GetTokenExpirationIso(), record.Locked, record.FailedAttempts)
    defer stmt.Close()

    if err != nil {
        log.Fatal(err)
        return nil, err, false
    }

    _ = tx.Commit()

    // do this to get the userid generated by the database
    returnRecord, _ := d.GetInternalAuthRecord(record.User)

    return returnRecord, nil, true
}

func (d *DriverSql) GetInternalAuthRecord(user string) (AuthInternalRecord, error) {
    rows, err := d.db.Query("SELECT userid, username, email, password, resettoken, tokenexpiration, locked, failedattempts FROM users WHERE type='internal' and username=?", user)
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()

    if !rows.Next() {
        return nil, nil
    }

    record := newRecord(rows)

    return record, nil
}

func (d *DriverSql) GetInternalAuthRecordByEmail(email string) (AuthInternalRecord, error) {
    rows, err := d.db.Query("SELECT userid, username, email, password, resettoken, tokenexpiration, locked, failedattempts FROM users WHERE type='internal' and email=?", email)
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()

    if !rows.Next() {
        return nil, nil
    }

    record := newRecord(rows)

    return record, nil
}

func newRecord(rows *sql.Rows) *BasicInternalAuthRecord {
    record := BasicInternalAuthRecord{}

    var stime string
    err := rows.Scan(&record.UserId, &record.User, &record.Email, &record.Password, &record.ResetToken, &stime, &record.Locked, &record.FailedAttempts)
    record.SetTokenExpirationIso([]byte(stime))

    if err != nil {
        log.Fatal(err)
    }

    return &record
}

// update
func (d *DriverSql) UpdateInternalAuthRecord(record AuthInternalRecord) error {

    var tx *sql.Tx
    var err error
    var rows *sql.Rows

    tx, err = d.db.Begin()
    if err != nil {
        log.Fatal(err)
        _ = tx.Rollback()
        return err
    }

    // need to make sure there is no conflict with new username and new email
    rows, err = d.db.Query("SELECT COUNT(*) FROM users WHERE type='internal' and email=? and userid<>?", record.GetEmail(), record.GetUserId())
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

    rows, err = d.db.Query("SELECT COUNT(*) FROM users WHERE type='internal' and user=? and userid<>?", record.GetUser(), record.GetUserId())
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
    stmt, err := tx.Prepare("UPDATE users SET username=?, email=?, password=?, resettoken=?, tokenexpiration=?, locked=?, failedattempts=? WHERE type='internal' AND userid=?")
    if err != nil {
        log.Fatal(err)
        _ = tx.Rollback()
        return err
    }

    _, err = stmt.Exec(record.GetUser(), record.GetEmail(), record.GetEncryptedPassword(), record.GetResetToken(), record.GetTokenExpirationIso(), record.IsLocked(), record.GetFailedAttempts(), record.GetUserId())
    defer stmt.Close()

    if err != nil {
        log.Fatal(err)
        return err
    }

    _ = tx.Commit()

    return nil
}

