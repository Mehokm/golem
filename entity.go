package golem

import (
	"errors"
	"reflect"
)

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

func (ep entityProtector) encrypt(field reflect.Value) {
	switch field.Interface().(type) {
	case []byte:
		field.SetBytes(ep.cipher.Encrypt(field.Bytes()))
	case string:
		field.SetString(string(ep.cipher.Encrypt([]byte(field.String()))))
	}
}

func (ep entityProtector) decrypt(field reflect.Value) error {
	switch field.Interface().(type) {
	case []byte:
		decrypted, err := ep.cipher.Decrypt(field.Bytes())

		if err != nil {
			return err
		}

		field.SetBytes(decrypted)
	case string:
		decrypted, err := ep.cipher.Decrypt([]byte(field.String()))

		if err != nil {
			return err
		}

		field.SetString(string(decrypted))
	}

	return nil
}

func (ep entityProtector) process(i interface{}, method string) error {
	iAddr := reflect.ValueOf(i)

	if iAddr.Kind() != reflect.Ptr {
		return errors.New("not a pointer value")
	}

	if iAddr.Elem().Kind() != reflect.Struct {
		return errors.New("interface{} must be of type Struct")
	}

	iAddrElem := iAddr.Elem()
	for i := 0; i < iAddrElem.NumField(); i++ {
		field := iAddrElem.Field(i)
		tag := iAddrElem.Type().Field(i).Tag.Get("golem")

		if tag != "protect" {
			continue
		}

		if method == "encrypt" {
			ep.encrypt(field)
		} else if method == "decrypt" {
			err := ep.decrypt(field)

			if err != nil {
				return err
			}
		}
	}
	return nil
}
