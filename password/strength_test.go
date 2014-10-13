package password

import (
	"testing"
)

func TestMinLength(t *testing.T) {
	messageExpectTrue := "Expected true on the following input: `%v`, `%v`"
	messageExpectFalse := "Expected false on the following input: `%v`, `%v`"

	var min int
	var str string
	var fn PasswordStrengthFunc

	min = 5
	fn = MinLengthFn(min)

	str = ""

	if fn(str) {
		t.Errorf(messageExpectFalse, min, str)
	}

	str = "1243"

	if fn(str) {
		t.Errorf(messageExpectFalse, min, str)
	}

	str = "12435"

	if !fn(str) {
		t.Errorf(messageExpectTrue, min, str)
	}

	min = 3
	fn = MinLengthFn(min)

	str = "今日"

	if fn(str) {
		t.Errorf(messageExpectFalse, min, str)
	}

	str = "今日!"

	if !fn(str) {
		t.Errorf(messageExpectTrue, min, str)
	}

	str = "今日!?"

	if !fn(str) {
		t.Errorf(messageExpectTrue, min, str)
	}

}

func TestContainsNonAlpha(t *testing.T) {
	messageExpectTrue := "Expected true on the following input: `%v`"
	messageExpectFalse := "Expected false on the following input: `%v`"

	var str string
	var fn PasswordStrengthFunc

	fn = ContainsNonAlphaFn()

	str = ""

	if fn(str) {
		t.Errorf(messageExpectFalse, str)
	}

	str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	if fn(str) {
		t.Errorf(messageExpectFalse, str)
	}

	str = "abcdefghijklmnopqrstuvwxyz."
	if !fn(str) {
		t.Errorf(messageExpectTrue, str)
	}

	str = "num1"
	if !fn(str) {
		t.Errorf(messageExpectTrue, str)
	}

	str = "漢字"
	if !fn(str) {
		t.Errorf(messageExpectTrue, str)
	}
}

func TestContainsNonAlphaNumeric(t *testing.T) {
	messageExpectTrue := "Expected true on the following input: `%v`"
	messageExpectFalse := "Expected false on the following input: `%v`"

	var str string
	var fn PasswordStrengthFunc

	fn = ContainsNonAlphaNumericFn()

	str = ""

	if fn(str) {
		t.Errorf(messageExpectFalse, str)
	}

	str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	if fn(str) {
		t.Errorf(messageExpectFalse, str)
	}

	str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

	if !fn(str) {
		t.Errorf(messageExpectTrue, str)
	}

	str = "John Smith"

	if !fn(str) {
		t.Errorf(messageExpectTrue, str)
	}

	str = "1.0"
	if !fn(str) {
		t.Errorf(messageExpectTrue, str)
	}

	str = "NUM_2"
	if !fn(str) {
		t.Errorf(messageExpectTrue, str)
	}

	str = "漢字"
	if !fn(str) {
		t.Errorf(messageExpectTrue, str)
	}

	str = "Çava"
	if !fn(str) {
		t.Errorf(messageExpectTrue, str)
	}
}
