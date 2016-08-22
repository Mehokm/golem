package golem

import (
	"bytes"
	"testing"
)

type TestStruct struct {
	A []byte `golem:"protect"`
	B string `golem:"protect"`
	C int
}

func TestEntityProtectUnprotect(t *testing.T) {
	cipher := NewAES256Cipher(ModeCBC)
	cipher.SetKey("test123abvefd1jhf123")

	ep := NewEntityProtector(cipher)

	ts := TestStruct{
		[]byte("12345"),
		"good bye",
		123,
	}

	ep.Protect(&ts)

	ep.Unprotect(&ts)

	if !bytes.Equal([]byte("12345"), ts.A) {
		t.Errorf("Excepted '%v' to equal '%v'", ts.B, []byte("12345"))
	}

	if "good bye" != ts.B {
		t.Errorf("Excepted '%v' to equal '%v'", ts.B, "good bye")
	}
}

func TestEntityReturnsErrorWhenNotAPointer(t *testing.T) {
	cipher := NewAES256Cipher(ModeCBC)
	cipher.SetKey("test123abvefd1jhf123")

	ep := NewEntityProtector(cipher)

	ts := TestStruct{
		[]byte("12345"),
		"good bye",
		123,
	}

	err := ep.Protect(ts)

	if "not a pointer value" != err.Error() {
		t.Errorf("Excepted '%v' to equal '%v'", err.Error(), "not a pointer value")
	}
}

func TestEntityReturnsErrorWhenNotAStruct(t *testing.T) {
	cipher := NewAES256Cipher(ModeCBC)
	cipher.SetKey("test123abvefd1jhf123")

	ep := NewEntityProtector(cipher)

	var ts interface{}

	err := ep.Protect(&ts)

	if "interface{} must be of type Struct" != err.Error() {
		t.Errorf("Excepted '%v' to equal '%v'", err.Error(), "interface{} must be of type Struct")
	}
}
