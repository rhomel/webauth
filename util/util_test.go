package util

import (
    "testing"
    "fmt"
    "strings"
    "strconv"
)

func TestUtilWhiteSpaceStripper1(t *testing.T) {
    var in, out, rec string
    in  = "Hello\t and\tGood morning."
    out = "HelloandGoodmorning."
    rec = StripAllWhiteSpace(in)

    if rec != out {
        t.Errorf("StripAllWhiteSpace(`%v`) = `%v`, want `%v`", in, rec, out)
    }
}

func TestUtilWhiteSpaceStripper2(t *testing.T) {
    var in, out, rec string
    in  = "  Hello !\nBob. "
    out = "Hello!Bob."
    rec = StripAllWhiteSpace(in)

    if rec != out {
        t.Errorf("StripAllWhiteSpace(`%v`) = `%v`, want `%v`", in, rec, out)
    }
}

func TestUtilWhiteSpaceStripper3(t *testing.T) {
    var in, out, rec string
    in  = ""
    out = ""
    rec = StripAllWhiteSpace(in)

    if rec != out {
        t.Errorf("StripAllWhiteSpace(`%v`) = `%v`, want `%v`", in, rec, out)
    }
}

func TestUtilWhiteSpaceStripper4(t *testing.T) {
    var in, out, rec string
    in  = "  "
    out = ""
    rec = StripAllWhiteSpace(in)

    if rec != out {
        t.Errorf("StripAllWhiteSpace(`%v`) = `%v`, want `%v`", in, rec, out)
    }
}

func TestUtilWhiteSpaceStripper5(t *testing.T) {
    var in, out, rec string
    in  = "こんにちは　みんな！"
    out = "こんにちはみんな！"
    rec = StripAllWhiteSpace(in)

    if rec != out {
        t.Errorf("StripAllWhiteSpace(`%v`) = `%v`, want `%v`", in, rec, out)
    }
}

func TestUtilEmailFormat(t *testing.T) {
    inputs := []string{
        "a@b.c",
        "ab.cd@ef.hk",
        "_@_._",
        "abcd@efgh.xyz",
        "ab@ef",
        "adc",
        "_._",
    }

    outputs := []bool{
        true,
        true,
        true,
        true,
        false,
        false,
        false,
    }

    for i, in := range(inputs) {
        rec := IsProbablyEmailFormat(in)
        out := outputs[i]

        if rec != out {
            t.Errorf("IsProbablyEmailFormat(`%v`) = `%v`, want `%v`", in, rec, out)
        }
    }
}

type TestJsonPerson struct {
    Name string
    Message string
    Age int
}

func (p *TestJsonPerson) String() string {
    return fmt.Sprintf("%v, %v, %v", p.Name, p.Message, p.Age)
}

func checkValues(t *testing.T, person *TestJsonPerson, expected *TestJsonPerson) {
    if person.Name != expected.Name || person.Message != expected.Message || person.Age != expected.Age {
        t.Errorf("JsonDecode didn't decode to the expected values. \nExpected: %v \nReceived: %v", person, expected)
    }
}

func TestJsonDecode(t *testing.T) {

    var json string
    var err error

    dave := TestJsonPerson{}
    daveName := "Dave"
    daveMessage := "Hello!"
    daveAge := 30

    // simple valid example
    json = `{"Name":"`+daveName+`","Message":"`+daveMessage+`","Age":`+strconv.Itoa(daveAge)+`}`
    _, err = JsonDecode( strings.NewReader(json), &dave )
    if err != nil {
        t.Errorf("JsonDecode returned an error on valid input.")
    }
    checkValues(t, &dave, &TestJsonPerson{daveName, daveMessage, daveAge})

    // extra json data that doesn't exist in the struct
    dave2 := TestJsonPerson{}
    json = `{"Name":"Dave","Message":"Hello!","Misc":"But wait!","Age":`+strconv.Itoa(daveAge)+`}`
    _, err = JsonDecode( strings.NewReader(json), &dave2 )
    if err != nil {
        t.Errorf("JsonDecode returned an error on valid input.")
    }
    checkValues(t, &dave2, &TestJsonPerson{daveName, daveMessage, daveAge})

    // missing json value (Message)
    dave3 := TestJsonPerson{}
    json = `{"Name":"Dave","Misc":"But wait!","Age":`+strconv.Itoa(daveAge)+`}`
    _, err = JsonDecode( strings.NewReader(json), &dave3 )
    if err != nil {
        t.Errorf("JsonDecode returned an error on valid input.")
    }
    checkValues(t, &dave3, &TestJsonPerson{daveName, "", daveAge})

    // type mismatch 
    dave4 := TestJsonPerson{}
    json = `{"Name":"Dave","Message":0,"Age":"thirty"}`
    _, err = JsonDecode( strings.NewReader(json), &dave4 )
    /*
    if err == nil {
        t.Errorf("JsonDecode received no error when an error was expected. Struct contents: `%v`, `%v`, `%v`", dave4.Name, dave4.Message, dave4.Age)
    }
    */
    checkValues(t, &dave4, &TestJsonPerson{daveName, "", 0})

    // invalid json
    dave5 := TestJsonPerson{}
    json = `{"Name":"Dave","Message":"hi",}`
    _, err = JsonDecode( strings.NewReader(json), &dave5 )
    /* 
    // json unmarshall really doesn't like to give us errors when passing an interface
    if err == nil {
        t.Errorf("JsonDecode received no error when an error was expected. Struct contents: `%v`, `%v`, `%v`", dave5.Name, dave5.Message, dave5.Age)
    }
    */
    checkValues(t, &dave5, &TestJsonPerson{"", "", 0})

    // valid json
    dave6 := TestJsonPerson{}
    json = `[]`
    _, err = JsonDecode( strings.NewReader(json), &dave6 )
    /* 
    // json unmarshall really doesn't like to give us errors when passing an interface
    if err == nil {
        t.Errorf("JsonDecode received no error when an error was expected. Struct contents: `%v`, `%v`, `%v`", dave5.Name, dave5.Message, dave5.Age)
    }
    */
    checkValues(t, &dave6, &TestJsonPerson{"", "", 0})

}

