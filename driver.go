package webauth

import "fmt"
import "log"
import "time"
import "crypto/rand"
import "code.google.com/p/go.crypto/bcrypt"

type AuthBaseRecord interface {
    GetUser() string
    GetEmail() string
    GetServiceType() string
}

type AuthExternalDriver interface {
    Initialize() error
    IsInitialized() bool
    GetServiceType() string // e.g. oauth/google, oauth/facebook
    StoreExternalAuthRecord(AuthBaseRecord) // insert/update
    GetExternalAuthRecord(string) AuthBaseRecord
    GetExternalAuthRecordByEmail(string) AuthBaseRecord
}

type AuthInternalRecord interface {
    AuthBaseRecord
    GetUserId() int
    GetEncryptedPassword() []byte
    GetResetToken() string
    GetTokenExpiration() time.Time
    IsLocked() bool
    GetFailedAttempts() int
    SetPassword(string)
    GetTokenExpirationIso() []byte

    InitResetToken() string // return reset token
    RetrieveResetToken() (string, bool) // token, expired
    Authenticate(string) bool // pass in unencrypted password
}

type AuthInternalDriver interface {
    Initialize() error
    IsInitialized() bool
    NewInternalAuthRecord(string,string,string) (AuthInternalRecord, error, bool) // insert
    GetInternalAuthRecord(string) (AuthInternalRecord, error)
    GetInternalAuthRecordByEmail(string) (AuthInternalRecord, error)
    UpdateInternalAuthRecord(AuthInternalRecord) error// update
}

/*
Encapsulates a basic internal authentication record that 
adheres to the AuthInternalRecord interface.

This is provided to make writing internal drivers easier. The 
storage driver's main responsibility is to serialize the data.
*/
type BasicInternalAuthRecord struct {
    UserId int
    User string
    Password []byte
    Email string
    ResetToken string
    TokenExpiration time.Time
    Locked bool
    FailedAttempts int
    // TODO add password expiration field
}

func NewBasicInternalAuthRecord(user string, email string) *BasicInternalAuthRecord {
    record := new(BasicInternalAuthRecord)
    record.User = user
    record.Email = email
    record.SetPassword(randString(64)) // random password
    return record
}

func (r *BasicInternalAuthRecord) String() string {
    return fmt.Sprintf("{'UserId':%d,'User':'%v','Password':'%v','Email':'%v','ResetToken':'%v','TokenExpiration':'%v','Locked':%t,'FailedAttempts':%d}",
        r.UserId,
        r.User,
        string(r.Password),
        r.Email,
        r.ResetToken,
        string(r.GetTokenExpirationIso()),
        r.Locked,
        r.FailedAttempts,
    )
}

func (r *BasicInternalAuthRecord) GetServiceType() string {
    return "internal"
}

func (r *BasicInternalAuthRecord) GetUserId() int {
    return r.UserId
}

func (r *BasicInternalAuthRecord) GetUser() string {
    return r.User
}

func (r *BasicInternalAuthRecord) GetEncryptedPassword() []byte {
    return r.Password
}

func (r *BasicInternalAuthRecord) GetEmail() string {
    return r.Email
}

func (r *BasicInternalAuthRecord) GetResetToken() string {
    return r.ResetToken
}

func (r *BasicInternalAuthRecord) GetTokenExpiration() time.Time {
    return r.TokenExpiration
}

func (r *BasicInternalAuthRecord) GetFailedAttempts() int {
    return r.FailedAttempts
}

func (r *BasicInternalAuthRecord) SetPassword(password string) {
    encrypted, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        log.Fatal(err)
    }
    r.Password = encrypted
}

func (r *BasicInternalAuthRecord) Authenticate(password string) bool {
    return bcrypt.CompareHashAndPassword(r.Password, []byte(password)) == nil
}

func (r *BasicInternalAuthRecord) InitResetToken() string {
    r.ResetToken = randString(64)
    r.TokenExpiration = time.Now()
    r.TokenExpiration.AddDate(0,0,1) // +1 day
    return r.ResetToken
}

func (r *BasicInternalAuthRecord) RetrieveResetToken() (string, bool) {
    valid := time.Now()
    valid.AddDate(0,0,-1) // -1 day
    exp := r.TokenExpiration.After(valid)
    return r.ResetToken, exp
}

func (r *BasicInternalAuthRecord) IsLocked() bool {
    return r.Locked
}

func (r *BasicInternalAuthRecord) GetTokenExpirationIso() []byte {
    b, _ := r.TokenExpiration.MarshalText()
    return b
}

func (r *BasicInternalAuthRecord) SetTokenExpirationIso(time []byte) {
    err := r.TokenExpiration.UnmarshalText(time)
    if err != nil {
        log.Fatal(err)
    }
}

func randString(n int) string {
    const alphanum = "-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    var bytes = make([]byte, n)
    rand.Read(bytes)
    for i, b := range bytes {
        bytes[i] = alphanum[b % byte(len(alphanum))]
    }
    return string(bytes)
}

type BasicExternalAuthRecord struct {
    User string
    Email string
    ServiceType string
}

func (r BasicExternalAuthRecord) GetUser() string {
    return r.User
}

func (r BasicExternalAuthRecord) GetEmail() string {
    return r.Email
}

func (r BasicExternalAuthRecord) GetServiceType() string {
    return r.ServiceType
}

func NewBasicExternalAuthRecord(user string, email string, service string) *BasicExternalAuthRecord {
    return &BasicExternalAuthRecord{user, email, service}
}

