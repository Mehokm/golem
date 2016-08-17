package golem

import (
	"bytes"
	"testing"
)

func TestAESCipherWithModeCBC(t *testing.T) {
	cipher := NewAESCipher(ModeCBC)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("test example key!1")

	testCipher(t, cipher)
}

func TestAESCipherWithModeCFB(t *testing.T) {
	cipher := NewAESCipher(ModeCFB)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("test example key!2")

	testCipher(t, cipher)
}

func TestAESCipherWithModeCTR(t *testing.T) {
	cipher := NewAESCipher(ModeCTR)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("test example key!3")

	testCipher(t, cipher)
}

func TestAESCipherWithModeOFB(t *testing.T) {
	cipher := NewAESCipher(ModeOFB)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("test example key!4")

	testCipher(t, cipher)
}

func TestAESModeCBCDecryptReturnsCorrectErrorWhenTooShort(t *testing.T) {
	cipher := NewAESCipher(ModeCBC)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("kdsfjas;k@!$KFNMSDFMS")

	testText := []byte("test example string ¬¨ˆ¥®†§!@#$%^&*()")

	enc := cipher.Encrypt(testText)
	_, err := cipher.Decrypt(enc[1:2])

	if "ciphertext is too short" != err.Error() {
		t.Errorf("Excepted '%v' to equal '%v'", err.Error(), "ciphertext is too short")
	}
}

func TestAESModeCBCDecryptReturnsCorrectErrorWhenNotMultipleOfBlock(t *testing.T) {
	cipher := NewAESCipher(ModeCBC)
	cipher.SetKeyLength(AES256)
	cipher.SetKey("kdsfjas;k@!$KFNMSDFMS")

	testText := []byte("test example string ¬¨ˆ¥®†§!@#$%^&*()")

	enc := cipher.Encrypt(testText)
	_, err := cipher.Decrypt(enc[1:])

	if "ciphertext is not a multiple of the block size" != err.Error() {
		t.Errorf("Excepted '%v' to equal '%v'", err.Error(), "ciphertext is not a multiple of the block size")
	}
}

func testCipher(t *testing.T, cipher Cipher) {
	testText := []byte("test example string ¬¨ˆ¥®†§!@#$%^&*()")

	enc := cipher.Encrypt(testText)
	dec, _ := cipher.Decrypt(enc)

	if bytes.Compare(testText, dec) != 0 {
		t.Error("decrypted text does not match test text")
	}
}
