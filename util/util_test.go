package util

import "testing"

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

