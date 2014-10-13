/*
Simple web server authentication with JSON transport.

The basic purpose is to allow internal and external (oauth) authentication with
minimal configuration on anything supporting the default HTTP server implementation.

By "minimal configuration" we mean minimal Go code to support using the package.
There will obviously be necessary customization with client served HTML, but all
necessary routes to support authentication and user-management on the back-end
will be provided.
*/
package webauth

import "net/http"
import "net/url"
import "encoding/json"
import "github.com/gorilla/securecookie"
import "encoding/hex"
import "io"
import "bufio"
import "io/ioutil"
import "os"
import "log"

import "github.com/rhomel/webauth/mailer"
import "github.com/rhomel/webauth/util"
import "github.com/rhomel/webauth/password"

const JsonMimeType string = "application/json"
const MessageInvalidLogin = "invalid username or password"
const MessageExpiredToken = "token has expired"
const MessageValidLogin = "logged in"

const CookieName = "login"

const DefaultHandlerPrefix = "/auth"

// Minimum requirements we need in a handler in order to register ourself
type MinHandler interface {
	Handle(string, http.Handler)
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}

// Paths for particular auth-related resources.
type RedirectPaths struct {
	SuccessfulLogin    string
	LoginForm          string
	ForgotPasswordForm string
	ResetPasswordForm  string
	NewAccountForm     string
}

type loginInput struct {
	User     string
	Password string
}

type newAccountInput struct {
	User     string
	Password string
	Email    string
}

type resetTokenInput struct {
	User string
}

type changePasswordTokenInput struct {
	User        string
	NewPassword string
	Token       string
}

type changePasswordInput struct {
	User        string
	Password    string
	NewPassword string
}

type ResponseJson struct {
	Success int
	Error   string
}

type ConfigError struct {
	HashKeyMessage  string
	BlockKeyMessage string
}

func (e *ConfigError) Error() {
	var fullmessage string
	if e.HashKeyMessage != "" {
		fullmessage = fullmessage + e.HashKeyMessage + "\n"
	}
	if e.BlockKeyMessage != "" {
		fullmessage = fullmessage + e.BlockKeyMessage + "\n"
	}
	return
}

// HashKey and BlockKey must be defined by the user of the library
type AuthenticationHandler struct {
	AuthPathPrefix   string
	HashKey          string // string in hex, the string will be decoded from hex characters to binary
	BlockKey         string // string in hex, the string will be decoded from hex characters to binary
	In               MinHandler
	Out              http.Handler
	CookieCoder      *securecookie.SecureCookie
	internalDriver   AuthInternalDriver
	externalDrivers  map[string]AuthExternalDriver
	ResetTokenMailer mailer.ResetMailer
	Redirects        *RedirectPaths
	Log              *log.Logger
	LogFile          *bufio.Writer
	StrengthFn       password.PasswordStrengthFunc
}

/*
Create a new Authentication handler.

hashkey and blockkey must be defined.
*/
func NewAuthenticationHandler(hashkey string, blockkey string, paths RedirectPaths) *AuthenticationHandler {

	handler := new(AuthenticationHandler)
	handler.HashKey = hashkey
	handler.BlockKey = blockkey
	handler.AuthPathPrefix = DefaultHandlerPrefix
	handler.Redirects = &paths

	shouldPanic := false
	err := new(ConfigError)

	if handler.HashKey == "" {
		shouldPanic = true
		err.HashKeyMessage = "A Hash Key needs to be defined"
	}

	if handler.BlockKey == "" {
		shouldPanic = true
		err.BlockKeyMessage = "A Block Key needs to be defined"
	}

	if shouldPanic {
		panic(err)
	}

	// setup the cookie value encoder/decoder
	hashKeyDecoded, decodeError := hex.DecodeString(handler.HashKey)
	if decodeError != nil {
		panic(decodeError)
	}

	blockKeyDecoded, decodeError := hex.DecodeString(handler.BlockKey)
	if decodeError != nil {
		panic(decodeError)
	}

	handler.CookieCoder = securecookie.New(hashKeyDecoded, blockKeyDecoded)

	handler.externalDrivers = make(map[string]AuthExternalDriver)

	logfile, logerr := os.Create("auth.log")
	if logerr != nil {
		log.Fatal(logerr)
		return nil
	}
	handler.LogFile = bufio.NewWriter(logfile)
	handler.Log = log.New(handler.LogFile, "", log.LstdFlags)

	return handler
}

// Register the token mailer. If no mailer is registered, emails will not be sent.
func (a *AuthenticationHandler) RegisterResetTokenMailer(m mailer.ResetMailer) {
	a.ResetTokenMailer = m
}

/*
Register a password strength function. If no password strength function is registered
the only password requirement is a non-empty string.
*/
func (a *AuthenticationHandler) RegisterPasswordStrengthFn(fn password.PasswordStrengthFunc) {
	a.StrengthFn = fn
}

/*
Set the internal driver. Note: you can only have one internal driver.
*/
func (a *AuthenticationHandler) SetInternalDriver(driver AuthInternalDriver) {
	a.internalDriver = driver
}

/*
Add an external driver. You can have multiple external drivers since
external drivers often delegate authentication to external systems.

AuthenticationHandler stores the driver by GetServiceType, so if you
add the same driver with the same service type twice, the last
the first add is overwritten by the second.
*/
func (a *AuthenticationHandler) AddExternalDriver(driver AuthExternalDriver) {
	key := driver.GetServiceType()
	a.externalDrivers[key] = driver
}

/*
Initialize drivers.

Returns the number of *unique* initialized drivers. For example
if you use a single driver but multiple times for different services,
then you should receive 1 as the return value, not the number of times
you added the driver.
*/
func (a *AuthenticationHandler) initializeDrivers() int {
	var count int

	// internal driver first
	if a.internalDriver != nil && !a.internalDriver.IsInitialized() {

		if err := a.internalDriver.Initialize(); err != nil {
			panic(err)
		}

		count++
	}

	// external drivers
	for _, extDriver := range a.externalDrivers {
		if !extDriver.IsInitialized() {
			if err := extDriver.Initialize(); err != nil {
				panic(err)
			}

			count++
		}
	}

	return count
}

/*
Register the authentication handler with an input handler and output handler.

The input handler is a MinHandler of your choice and where all http handlers are
registered to, for example an http.ServeMux or a Gorilla toolkit mux.Router. If
the input MinHandler is nil, then the default http.Handle will be used.

The output handler is where authenticated requests are forwarded to. Non-authenticated
requests will be denied with predefined error messages. The output handler can be nil,
however this results in a not-very useful web app.
*/
func (a *AuthenticationHandler) RegisterHandlers(in MinHandler, out http.Handler) {

	a.In = in
	a.Out = out

	registerFn := http.HandleFunc
	registerFnHandle := http.Handle

	if a.In != nil {
		registerFn = a.In.HandleFunc
		registerFnHandle = a.In.Handle
	}

	if a.internalDriver != nil {
		a.Log.Println("Registering internal driver HTTP handles")

		a.Log.Println(a.AuthPathPrefix + "/internal/json/authenticate")
		registerFn(a.AuthPathPrefix+"/internal/json/authenticate", func(w http.ResponseWriter, r *http.Request) {
			a.serveJsonAuthenticate(w, r)
		})

		a.Log.Println(a.AuthPathPrefix + "/internal/json/new")
		registerFn(a.AuthPathPrefix+"/internal/json/new", func(w http.ResponseWriter, r *http.Request) {
			a.serveJsonNewAccount(w, r)
		})

		a.Log.Println(a.AuthPathPrefix + "/internal/json/password/reset")
		registerFn(a.AuthPathPrefix+"/internal/json/password/reset", func(w http.ResponseWriter, r *http.Request) {
			a.serveJsonPasswordReset(w, r)
		})

		a.Log.Println(a.AuthPathPrefix + "/internal/json/password/token")
		registerFn(a.AuthPathPrefix+"/internal/json/password/token", func(w http.ResponseWriter, r *http.Request) {
			a.serveJsonPasswordToken(w, r)
		})

		a.Log.Println(a.AuthPathPrefix + "/internal/json/password/change")
		registerFn(a.AuthPathPrefix+"/internal/json/password/change", func(w http.ResponseWriter, r *http.Request) {
			a.serveJsonPasswordChange(w, r)
		})

		a.LogFile.Flush()
	}

	/*
	   registerFn(a.AuthPathPrefix + "/internal/std/authenticate", func(w http.ResponseWriter, r *http.Request) {
	       a.serveStdAuthenticate(w,r)
	   })

	   registerFn(a.AuthPathPrefix + "/internal/std/password/reset", func(w http.ResponseWriter, r *http.Request) {
	       a.serveStdPasswordReset(w,r)
	   })

	   registerFn(a.AuthPathPrefix + "/internal/std/password/token", func(w http.ResponseWriter, r *http.Request) {
	       a.serveStdPasswordToken(w,r)
	   })

	   registerFn(a.AuthPathPrefix + "/internal/std/password/change", func(w http.ResponseWriter, r *http.Request) {
	       a.serveStdPasswordToken(w,r)
	   })
	*/

	if driverCount := a.initializeDrivers(); driverCount == 0 {
		panic("No authentication drivers were initialized. Drivers need to be added before webauth.RegisterHandlers is called.")
	}

	// register catch-all rule
	registerFnHandle("/", a)
}

/*
Login the user if the given username/password combination is valid.
*/
func (a *AuthenticationHandler) serveJsonAuthenticate(w http.ResponseWriter, r *http.Request) {

	var input = loginInput{}

	body, _ := ioutil.ReadAll(io.LimitReader(r.Body, 1000))
	json.Unmarshal(body, &input)

	record, err := a.internalDriver.GetInternalAuthRecord(input.User)

	if err != nil || record == nil {
		writeJsonInvalidLogin(w)
		return
	}

	// authenticate
	if record.Authenticate(input.Password) {
		// authenticated
		a.setAuthCookie(w, record)
		writeJsonValidLogin(w)
	} else {
		writeJsonInvalidLogin(w)
	}
}

/*
Create a new user account.
*/
func (a *AuthenticationHandler) serveJsonNewAccount(w http.ResponseWriter, r *http.Request) {

	var input = newAccountInput{}

	body, _ := ioutil.ReadAll(io.LimitReader(r.Body, 1000))
	json.Unmarshal(body, &input)

	input.User = util.StripAllWhiteSpace(input.User)
	input.Email = util.StripAllWhiteSpace(input.Email)

	if input.Email == "" {
		writeJsonError(w, "Email cannot be empty")
		return
	}

	if !util.IsProbablyEmailFormat(input.Email) {
		writeJsonError(w, "Not a valid email address")
		return
	}

	if input.User == "" {
		writeJsonError(w, "Username cannot be empty")
		return
	}

	if input.Password == "" {
		writeJsonError(w, "Password cannot be empty")
		return
	}

	if a.StrengthFn != nil && !a.StrengthFn(input.Password) {
		writeJsonError(w, "Password is too weak")
		return
	}

	_, err, ok := a.internalDriver.NewInternalAuthRecord(input.User, input.Email, input.Password)

	if err != nil {
		writeJsonError(w, "System Error")
		return
	}

	if !ok {
		writeJsonError(w, "Username or Email already registered.")
		return
	}

	writeJsonOk(w)
}

/*
Send the user an email with a reset password token.
*/
func (a *AuthenticationHandler) serveJsonPasswordToken(w http.ResponseWriter, r *http.Request) {

	var input = resetTokenInput{}

	body, _ := ioutil.ReadAll(io.LimitReader(r.Body, 1000))
	json.Unmarshal(body, &input)

	record, err := a.internalDriver.GetInternalAuthRecord(input.User)

	if err != nil {
		writeJsonInvalidLogin(w)
		return
	}

	// send email
	token := record.InitResetToken()

	if a.ResetTokenMailer != nil {
		a.ResetTokenMailer.Send(token, record.GetEmail())
	}

	writeJsonOk(w)
}

/*
Given a valid reset token, user name, and new password, reset the user's password.
*/
func (a *AuthenticationHandler) serveJsonPasswordReset(w http.ResponseWriter, r *http.Request) {

	var input = changePasswordTokenInput{}

	body, _ := ioutil.ReadAll(io.LimitReader(r.Body, 1000))
	json.Unmarshal(body, &input)

	record, err := a.internalDriver.GetInternalAuthRecord(input.User)

	if err != nil {
		writeJsonInvalidLogin(w)
		return
	}

	// verify token matches
	storedToken, expired := record.RetrieveResetToken()

	if expired {
		writeJsonExpiredToken(w)
		return
	}

	if storedToken != input.Token {
		writeJsonInvalidLogin(w)
		return
	}

	// reset the password
	record.SetPassword(input.NewPassword)
	err = a.internalDriver.UpdateInternalAuthRecord(record)
	if err != nil {
		writeJsonError(w, "Failed to update user record")
		return
	}

	writeJsonOk(w)
}

/*
Change the user's password given a valid username and old password.
*/
func (a *AuthenticationHandler) serveJsonPasswordChange(w http.ResponseWriter, r *http.Request) {

	var input = changePasswordInput{}

	body, _ := ioutil.ReadAll(io.LimitReader(r.Body, 1000))
	json.Unmarshal(body, &input)

	record, err := a.internalDriver.GetInternalAuthRecord(input.User)

	if err != nil {
		writeJsonInvalidLogin(w)
		return
	}

	// authenticate
	if record.Authenticate(input.Password) {
		// authenticated
		// reset the password
		record.SetPassword(input.NewPassword)
		err := a.internalDriver.UpdateInternalAuthRecord(record)
		if err != nil {
			writeJsonError(w, "Failed to update user record")
			return
		}

		writeJsonOk(w)
	} else {
		writeJsonInvalidLogin(w)
	}

}

func writeJsonInvalidLogin(w http.ResponseWriter) {
	writeJsonError(w, MessageInvalidLogin)
}

func writeJsonOk(w http.ResponseWriter) {
	var responseJson ResponseJson
	responseJson.Success = 1
	responseJson.Error = ""
	responseBytes, _ := json.Marshal(responseJson)
	w.Write(responseBytes)
}

func writeJsonError(w http.ResponseWriter, message string) {
	var responseJson ResponseJson
	responseJson.Success = 0
	responseJson.Error = message
	responseBytes, _ := json.Marshal(responseJson)
	w.Write(responseBytes)
}

func writeJsonValidLogin(w http.ResponseWriter) {
	writeJsonOk(w)
}

func writeJsonExpiredToken(w http.ResponseWriter) {
	writeJsonError(w, MessageExpiredToken)
}

func (a *AuthenticationHandler) setAuthCookie(w http.ResponseWriter, record AuthBaseRecord) {
	value := map[string]string{}

	value["user"] = record.GetUser()
	value["email"] = record.GetEmail()
	value["type"] = record.GetServiceType()

	if encodedValue, err := a.CookieCoder.Encode(CookieName, value); err == nil {

		cookie := &http.Cookie{
			Name:  CookieName,
			Value: encodedValue,
			Path:  "/",
		}
		http.SetCookie(w, cookie)

	} else {
		// TODO change this to a log
		panic("failed to encode user cookie!")
	}

}

/*
Intercept standard requests and if the current user is not logged in (no login cookie present)
then automatically forward to the authentication area (resource).
*/
func (a *AuthenticationHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {

	a.Log.Println("Authenticating for URL " + request.URL.String())
	a.LogFile.Flush()

	if cookie, err := request.Cookie(CookieName); err == nil {
		value := make(map[string]string)
		if err = a.CookieCoder.Decode(CookieName, cookie.Value, &value); err == nil {
			// valid cookie, forward request
			if a.Out != nil {
				a.Out.ServeHTTP(response, request)
				return
			}
		}
	}

	a.Log.Println("Not logged in, redirecting to login page.")
	for _, cookie := range request.Cookies() {
		a.Log.Printf("Request cookie: %v\n", cookie)
	}
	a.LogFile.Flush()

	// invalid cookie, or not logged in
	// forward to login
	http.Redirect(response, request, a.Redirects.LoginForm+"?requrl="+url.QueryEscape(request.URL.String()), http.StatusTemporaryRedirect)
}
