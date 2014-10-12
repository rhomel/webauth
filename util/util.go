/*
Utility functions (currently mostly string sanitizing functions)
*/
package util

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"regexp"
	"unicode"
)

var ReEmailFormat *regexp.Regexp
var Debugger bool // just storage, use Debug() to toggle

func init() {
	//ReStripWhiteSpace = regexp.MustCompile("\\s") // this doesn't strip unicode whitespace
	ReEmailFormat = regexp.MustCompile(".+\\@.+\\..+")

	DPrintf = dnoopPrintf
	DPrintln = dnoopPrintln
}

/*
Strip all whitespace (include Unicode whitespace) from a string.
*/
func StripAllWhiteSpace(s string) string {
	var buffer bytes.Buffer
	for _, runeval := range s {
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

/*
Decode a bunch of JSON (usually from an http Request body) into
a struct (or interface{}).

The read []byte body and an error (if any) are returned.
*/
func JsonDecode(body io.Reader, outputStruct interface{}) ([]byte, error) {

	byteBody, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, err
	}

	json.Unmarshal(byteBody, &outputStruct)

	return byteBody, err
}

/*
Same as JsonDecode but with a limit reader to limit the number of bytes read.
*/
func JsonDecodeLimit(body io.Reader, outputStruct interface{}, limit int64) ([]byte, error) {
	return JsonDecode(io.LimitReader(body, limit), outputStruct)
}

/*
Short-hand for JsonDecodeLimit(body, out, 1000)
*/
func JsonDecodeShort(body io.Reader, outputStruct interface{}) ([]byte, error) {
	return JsonDecodeLimit(body, outputStruct, 1000)
}

/*
Debug logging.
*/
var DPrintf func(string, ...interface{})
var DPrintln func(...interface{})

func debugOn() {
	DPrintf = log.Printf
	DPrintln = log.Println
}

func debugOff() {
	DPrintf = dnoopPrintf
	DPrintln = dnoopPrintln
}

/*
No operation.

DPrintf and DPrintln are set to this to turn off debuggin.
*/
func dnoopPrintf(s string, v ...interface{}) {
}
func dnoopPrintln(v ...interface{}) {
}

func Debug(on bool) {
	Debugger = on
	if on {
		debugOn()
	} else {
		debugOff()
	}
}
