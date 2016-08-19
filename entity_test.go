package golem

import (
	_ "fmt"
	"testing"
)

type TestStruct struct {
	A ByteArray
	B ByteArray
	C []byte
}

func TestEntityProtectUnprotect(t *testing.T) {
	cipher := NewAES256Cipher(ModeCBC)
	cipher.SetKey("test123abvefd1jhf123")

	ep := NewEntityProtector(cipher)

	ts := TestStruct{
		ByteArray("hello"),
		ByteArray("world"),
		[]byte("12345"),
	}

	ep.Protect(&ts)
	ep.Unprotect(&ts)

	if "hello" != ts.A.String() {
		t.Errorf("Excepted '%v' to equal '%v'", ts.A.String(), "hello")
	}

	if "world" != ts.B.String() {
		t.Errorf("Excepted '%v' to equal '%v'", ts.B.String(), "world")
	}
}

func TestEntityReturnsErrorWhenNotAPointer(t *testing.T) {
	cipher := NewAES256Cipher(ModeCBC)
	cipher.SetKey("test123abvefd1jhf123")

	ep := NewEntityProtector(cipher)

	ts := TestStruct{
		ByteArray("hello"),
		ByteArray("world"),
		[]byte("12345"),
	}

	err := ep.Protect(ts)

	if "Not a pointer value" != err.Error() {
		t.Errorf("Excepted '%v' to equal '%v'", err.Error(), "Not a pointer value")
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
