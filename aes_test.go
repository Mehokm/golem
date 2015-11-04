package golem

import (
	"bytes"
	"testing"
)

func TestCipherWithModeCBC(t *testing.T) {
	cipher := NewAESCipher(ModeCBC)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("test example key!1")

	testCipher(t, cipher)
}

func TestCipherWithModeCFB(t *testing.T) {
	cipher := NewAESCipher(ModeCFB)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("test example key!2")

	testCipher(t, cipher)
}

func TestCipherWithModeCTR(t *testing.T) {
	cipher := NewAESCipher(ModeCTR)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("test example key!3")

	testCipher(t, cipher)
}

func TestCipherWithModeOFB(t *testing.T) {
	cipher := NewAESCipher(ModeOFB)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("test example key!4")

	testCipher(t, cipher)
}

func testCipher(t *testing.T, cipher AESCipher) {
	testText := []byte("test example string ¬¨ˆ¥®†§!@#$%^&*()")

	enc := cipher.Encrypt(testText)
	dec := cipher.Decrypt(enc)

	if bytes.Compare(testText, dec) != 0 {
		t.Error("decrypted text does not match test text")
	}
}
