package webauth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	//sqlite "github.com/mattn/go-sqlite3"
	sqlite "github.com/rhomel/go-sqlite3" // Has Version func
	//"github.com/rhomel/webauth/util"
	//_ "github.com/mxk/go-sqlite/sqlite3"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
)

const ServerHost = "localhost:7777"
const DbFile = "./testcase.db"

const ProtectedResource = "/api/secretsauce"
const ProtectedResourceContent = "top-secret"

func init() {
	paths := RedirectPaths{}
	paths.SuccessfulLogin = "/test/success/login"
	paths.LoginForm = "/test/login"
	paths.ForgotPasswordForm = "/test/forgot"
	paths.ResetPasswordForm = "/test/reset"
	paths.NewAccountForm = "/test/newaccount"

	http.HandleFunc("/test/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "test")
	})

	apiMux := mux.NewRouter()
	apiMux.HandleFunc(ProtectedResource, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, ProtectedResourceContent)
	})

	setupServer(apiMux, paths)
}

func testHttpRequest(t *testing.T, httpVerb string, resourcePath string, inputJson string, cookies []*http.Cookie, wantError bool, outputVerifier func(*testing.T, *http.Response)) {

	client := new(http.Client)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return errors.New("redirect received")
	}

	body := bytes.NewReader([]byte(inputJson))

	resource := "http://" + ServerHost + resourcePath
	log.Println("[http client] Requesting: " + resource)

	req, err := http.NewRequest(httpVerb, resource, body)
	req.Header.Add("Content-Type", "application/json")

	if cookies != nil {
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
	}

	resp, err := client.Do(req)
	if err != nil && !wantError {
		log.Fatalf("Client request returned an error: %v", err)
	}

	if resp.StatusCode != 200 && !wantError {
		log.Fatalf("Server returned not-ok HTTP response code. Received code: %d", resp.StatusCode)
	}

	outputVerifier(t, resp)

}

func testJsonHttpRequest(t *testing.T, httpVerb string, resourcePath string, inputJson string, cookies []*http.Cookie, outputJsonVerifier func(*testing.T, map[string]interface{}, *http.Response)) {

	testHttpRequest(t, httpVerb, resourcePath, inputJson, cookies, false, func(t *testing.T, resp *http.Response) {
		var rjson map[string]interface{}

		rbody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error occurred during reading response Body")
		}

		json.Unmarshal(rbody, &rjson)

		// close body
		resp.Body.Close()

		outputJsonVerifier(t, rjson, resp)
	})

}

func testCreateNewAccount(t *testing.T, inputJson string, outputJsonVerifier func(*testing.T, map[string]interface{}, *http.Response)) {
	testJsonHttpRequest(t, "POST", "/auth/internal/json/new", inputJson, nil, outputJsonVerifier)
}

func testLogin(t *testing.T, inputJson string, outputJsonVerifier func(*testing.T, map[string]interface{}, *http.Response)) {
	testJsonHttpRequest(t, "POST", "/auth/internal/json/authenticate", inputJson, nil, outputJsonVerifier)
}

func verifyBasicErrorFunc(t *testing.T, rjson map[string]interface{}, response *http.Response) {
	if rjson == nil {
		t.Errorf("Received no response body")
		return
	}

	successCode := rjson["Success"].(float64)
	if successCode != 0 {
		t.Errorf("Received successful account creation code when expecting 0. Received: %v", successCode)
		return
	}

	errorMessage := rjson["Error"].(string)
	if errorMessage == "" {
		t.Errorf("Received empty error message.")
		return
	}
}

func verifyBasicSuccessFunc(t *testing.T, rjson map[string]interface{}, response *http.Response) {
	if rjson == nil {
		t.Errorf("Received no response body")
		return
	}

	if rjson["Success"].(float64) != 1 || rjson["Error"] != "" {
		t.Errorf("Didn't create the new user account correctly. Received: %v", rjson)
		return
	}
}

func TestNewAccountBasic(t *testing.T) {
	var json string
	json = `{"User":"bob","Password":"marley","Email":"deputy@example.com"}`
	testCreateNewAccount(t, json, verifyBasicSuccessFunc)
}

func TestNewAccountDuplicates(t *testing.T) {
	var json string

	// create an account
	json = `{"User":"joe","Password":"SuperSecret","Email":"joe@example.com"}`
	testCreateNewAccount(t, json, verifyBasicSuccessFunc)

	// try to create it again expecting an error
	testCreateNewAccount(t, json, verifyBasicErrorFunc)

	// try same username but different email
	json = `{"User":"joe","Password":"SuperSecret","Email":"joeblow@example.com"}`
	testCreateNewAccount(t, json, verifyBasicErrorFunc)

	// try different username but same email
	json = `{"User":"joeblow","Password":"SuperSecret","Email":"joe@example.com"}`
	testCreateNewAccount(t, json, verifyBasicErrorFunc)
}

func TestNewAccountMissingParametersNoUser(t *testing.T) {
	// no username
	json := `{"User":"","Password":"Such Forgettable","Email":"jane@example.com"}`
	testCreateNewAccount(t, json, verifyBasicErrorFunc)
}

func TestNewAccountMissingParametersNoPassword(t *testing.T) {
	// no password
	json := `{"User":"jane","Password":"","Email":"jane@example.com"}`
	testCreateNewAccount(t, json, verifyBasicErrorFunc)
}

func TestNewAccountMissingParametersNoEmail(t *testing.T) {
	// no email
	json := `{"User":"jane","Password":"Such Forgettable","Email":""}`
	testCreateNewAccount(t, json, verifyBasicErrorFunc)
}

func TestNewAccountMissingParametersWhiteSpaceUserName(t *testing.T) {
	// note: middle space is a non-breakable unicode space
	json := `{"User":" 　 ","Password":"Such Forgettable","Email":"jane@example.com"}`
	testCreateNewAccount(t, json, verifyBasicErrorFunc)
}

func TestLoginBasic(t *testing.T) {
	var json string
	json = `{"User":"alice","Password":"WONDerful","Email":"alice@example.com"}`
	testCreateNewAccount(t, json, verifyBasicSuccessFunc)

	var cookies []*http.Cookie

	// try logging in
	json = `{"User":"alice","Password":"WONDerful"}`
	testLogin(t, json, func(t *testing.T, rjson map[string]interface{}, response *http.Response) {

		if rjson == nil {
			t.Errorf("Received no response body")
			t.FailNow()
		}

		if rjson["Success"].(float64) != 1 || rjson["Error"] != "" {
			t.Errorf("Didn't create the new user account correctly. Received: %v", rjson)
			t.FailNow()
		}

		cookies = response.Cookies()
		found := false

		// look for the login cookie
		for _, cookie := range cookies {
			if cookie.Name == "login" {
				found = true
			}
		}

		if !found {
			t.Errorf("Didn't receive a login cookie.")
			t.FailNow()
		}
	})

	// try accessing a protected resource that requires login
	testHttpRequest(t, "GET", ProtectedResource, "", cookies, false, func(t *testing.T, response *http.Response) {
		rbody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalf("Error occurred during reading response Body")
		}

		if ProtectedResourceContent != string(rbody) {
			t.Errorf("Didn't get expected resource body. Expect `%v`. Received `%v`.", ProtectedResourceContent, string(rbody))
		}
	})

	// try accessing a protected resource without a cookie
	testHttpRequest(t, "GET", ProtectedResource, "", nil, true, func(t *testing.T, response *http.Response) {
		if response.StatusCode != 301 && response.StatusCode != 307 {
			t.Errorf("Didn't get a redirect for requesting a protected resource without a valid login cookie.")
		}
	})

}

func TestLoginIncorrectCreds(t *testing.T) {
	var json string
	json = `{"User":"daveh","Password":"p0wnnnd!","Email":"daveh@example.com"}`
	testCreateNewAccount(t, json, verifyBasicSuccessFunc)

	var cookies []*http.Cookie

	// try logging in (correctly)
	json = `{"User":"daveh","Password":"p0wnnnd!"}`
	testLogin(t, json, func(t *testing.T, rjson map[string]interface{}, response *http.Response) {

		if rjson == nil {
			t.Errorf("Received no response body")
			t.FailNow()
		}

		if rjson["Success"].(float64) != 1 || rjson["Error"] != "" {
			t.Errorf("Didn't create the new user account correctly. Received: %v", rjson)
			t.FailNow()
		}

		cookies = response.Cookies()
		found := false

		// look for the login cookie
		for _, cookie := range cookies {
			if cookie.Name == "login" {
				found = true
			}
		}

		if !found {
			t.Errorf("Didn't receive a login cookie.")
			t.FailNow()
		}
	})

	// try logging in (incorrectly)
	json = `{"User":"daveh","Password":"p0wnnd!"}`
	testLogin(t, json, func(t *testing.T, rjson map[string]interface{}, response *http.Response) {

		if rjson == nil {
			t.Errorf("Received no response body")
			t.FailNow()
		}

		if rjson["Success"].(float64) != 0 || rjson["Error"] == "" {
			t.Errorf("Didn't report expected failed login. Received: %v", rjson)
		}

		cookies = response.Cookies()
		found := false

		// look for the login cookie
		for _, cookie := range cookies {
			if cookie.Name == "login" {
				found = true
			}
		}

		if found {
			t.Errorf("Received login cookie when shouldn't have due to incorrect login.")
			t.FailNow()
		}
	})

	// try logging in (incorrectly again, this time with different user name)
	json = `{"User":"davehh","Password":"p0wnnnd!"}`
	testLogin(t, json, func(t *testing.T, rjson map[string]interface{}, response *http.Response) {

		if rjson == nil {
			t.Errorf("Received no response body")
			t.FailNow()
		}

		if rjson["Success"].(float64) != 0 || rjson["Error"] == "" {
			t.Errorf("Didn't report expected failed login. Received: %v", rjson)
		}

		cookies = response.Cookies()
		found := false

		// look for the login cookie
		for _, cookie := range cookies {
			if cookie.Name == "login" {
				found = true
			}
		}

		if found {
			t.Errorf("Received login cookie when shouldn't have due to incorrect login.")
			t.FailNow()
		}
	})
}

func setupServer(outputHandler http.Handler, paths RedirectPaths) {

	hashKey := "89408df15babfd94d259a508721e7cadf67cee8f731d8bba54c6426540e1e13de7c73ceed0c9d66571d5be8de19486431a0ac32307a6e3523a20f40a5e8f8d46"
	blockKey := "8ce6d0be2d7def9a73849748ea3ba6a21e4b82920282ee50d70f685d3e04ca92"

	var dbDriver string
	var db *sql.DB
	var err error

	// Select Database Type
	dbDriver = "sqlite3"
	//dbDriver = "postgres"
	log.Printf("Using database driver: %v", dbDriver)

	var cleanup func()
	if dbDriver == "sqlite3" {
		cleanup = func() {
			log.Println("Cleaning up test data.")
			_ = os.Remove(DbFile)
		}
	} else {
		cleanup = func() {
			log.Println("Cleaning up test data.")
			tx, err := db.Begin()
			_, err = tx.Exec("DELETE FROM users")
			if err != nil {
				log.Fatalln("Couldn't cleanup test data.")
			}
			if err := tx.Commit(); err != nil {
				log.Fatalln("Couldn't commit cleanup of test data.")
			}
		}
	}

	if dbDriver == "sqlite3" {
		cleanup() // cleanup test data from previous runs
	}

	var authDriver *DriverSql

	switch dbDriver {
	case "sqlite3":
		sqliteVersion, _, sqliteSourceId := sqlite.Version()
		log.Printf("SQLite version: %v, source id: %v\n", sqliteVersion, sqliteSourceId)
		/*
			authDriver = NewDriverSqlNoConnectionCache(dbDriver, func() (*sql.DB, error) {
				//return sql.Open(dbDriver, "testcase.db:locked.sqlite?cache=shared&mode=rwc")
				return sql.Open(dbDriver, DbFile)
			})
		*/
		db, err = sql.Open(dbDriver, DbFile)
		authDriver = NewDriverSql(dbDriver, db)
		//util.Debug(true)
	case "postgres":
		pgConnectionString := fmt.Sprintf("user=%v dbname=test sslmode=disable", os.Getenv("USER"))
		log.Printf("Postgres Connection String: %v\n", pgConnectionString)
		db, err = sql.Open(dbDriver, pgConnectionString)
		authDriver = NewDriverSql(dbDriver, db)
	}

	if err != nil {
		log.Fatal(err)
		return
	}
	if dbDriver != "sqlite3" {
		cleanup() // cleanup test data from previous runs
	}

	authHandler := NewAuthenticationHandler(hashKey, blockKey, paths)
	authHandler.SetInternalDriver(authDriver)
	authHandler.RegisterHandlers(nil, outputHandler) // in = nil : defaults to http.Handle/http.HandleFunc

	log.Println("Starting webserver...")

	go func() {
		http.ListenAndServe(ServerHost, nil)
	}()

}
