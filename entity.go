package golem

import (
	"errors"
	"reflect"
)

// ByteArray is a type that allows structs to be protected
type ByteArray []byte

type entityProtector struct {
	cipher Cipher
}

// NewEntityProtector returns an entityProtector with a cipher
func NewEntityProtector(cipher Cipher) entityProtector {
	return entityProtector{cipher}
}

func (ep entityProtector) Protect(i interface{}) error {
	return ep.process(i, "encrypt")
}

func (ep entityProtector) Unprotect(i interface{}) error {
	return ep.process(i, "decrypt")
}

func (ep entityProtector) process(i interface{}, method string) error {
	iAddr := reflect.ValueOf(i)

	if iAddr.Kind() != reflect.Ptr {
		return errors.New("Not a pointer value")
	}

	iAddr = reflect.Indirect(iAddr)

	if iAddr.Kind() != reflect.Struct {
		return errors.New("interface{} must be of type Struct")
	}

	iAddr = reflect.Indirect(iAddr)
	for i := 0; i < iAddr.NumField(); i++ {
		field := iAddr.Field(i)
		if _, ok := field.Interface().(ByteArray); ok {
			switch method {
			case "encrypt":
				field.SetBytes(ep.cipher.Encrypt(field.Bytes()))
			case "decrypt":
				decrypted, err := ep.cipher.Decrypt(field.Bytes())

				if err != nil {
					return err
				}

				field.SetBytes(decrypted)
			}
		}
	}
	return nil
}

// ToString returns string version of []byte
func (ba ByteArray) String() string {
	return string(ba)
}
