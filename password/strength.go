package password

/*
Functions for testing if a password is weak or not.

The webauth Authenticator will want a basic function that satisfies the
following signature:

	func(password string) bool // return true = password meets requirements

So this package provides functions for *creating* functions that satisfy
that signature.
*/

import (
	"regexp"
	"unicode/utf8"
)

// Password strength function signature (take a password, return true if it is strong)
type PasswordStrengthFunc func(string) bool

// return true if the password rune count is >= length
func MinLength(password string, length int) bool {
	return utf8.RuneCountInString(password) >= length
}

// generates a function that tests for rune counts
func MinLengthFn(length int) PasswordStrengthFunc {
	return func(password string) bool {
		return MinLength(password, length)
	}
}

// return true if there's at least 1 non-alpha character
func ContainsNonAlpha(password string) bool {
	re := regexp.MustCompile("[[:^alpha:]]")
	return re.MatchString(password)
}

// generates a function that test for non-alpha characters
func ContainsNonAlphaFn() PasswordStrengthFunc {
	return ContainsNonAlpha
}

// return true if there's at least 1 non-alpha-numeric character
func ContainsNonAlphaNumeric(password string) bool {
	re := regexp.MustCompile("[[:^alnum:]]")
	return re.MatchString(password)
}

// generates a function that test for non-alpha numeric characters
func ContainsNonAlphaNumericFn() PasswordStrengthFunc {
	return ContainsNonAlphaNumeric
}
