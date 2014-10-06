/*
Utility functions (currently mostly string sanitizing functions)
*/
package util

import "regexp"
import "unicode"
import "bytes"

var ReEmailFormat *regexp.Regexp

func init() {
    //ReStripWhiteSpace = regexp.MustCompile("\\s") // this doesn't strip unicode whitespace
    ReEmailFormat = regexp.MustCompile(".+\\@.+\\..+")
}

/*
Strip all whitespace (include Unicode whitespace) from a string.
*/
func StripAllWhiteSpace(s string) string {
    var buffer bytes.Buffer
    for _, runeval := range(s) {
        if !unicode.In(runeval, unicode.White_Space) {
            buffer.WriteRune(runeval)
        }
    }
    return buffer.String()
}

/*
Return true if the given string looks like an email address.

The email specification is really convoluted so we will only check 
for emails that follow the format: a@b.c
*/
func IsProbablyEmailFormat(email string) bool {
    return ReEmailFormat.MatchString(email)
}

