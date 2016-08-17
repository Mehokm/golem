package golem

import "testing"

func TestDESCipherWithModeCBC(t *testing.T) {
	cipher := NewDESCipher(ModeCBC)
	cipher.SetKey("test example key!1")

	testCipher(t, cipher)
}

func TestDESCipherWithModeCFB(t *testing.T) {
	cipher := NewDESCipher(ModeCFB)
	cipher.SetKey("test example key!2")

	testCipher(t, cipher)
}

func TestDESCipherWithModeCTR(t *testing.T) {
	cipher := NewDESCipher(ModeCTR)
	cipher.SetKey("test example key!3")

	testCipher(t, cipher)
}

func TestDESCipherWithModeOFB(t *testing.T) {
	cipher := NewDESCipher(ModeOFB)
	cipher.SetKey("test example key!4")

	testCipher(t, cipher)
}

func TestDESModeCBCDecryptReturnsCorrectErrorWhenTooShort(t *testing.T) {
	cipher := NewDESCipher(ModeCBC)
	cipher.SetKey("kdsfjas;k@!$KFNMSDFMS")

	testText := []byte("test example string ¬¨ˆ¥®†§!@#$%^&*()")

	enc := cipher.Encrypt(testText)
	_, err := cipher.Decrypt(enc[1:2])

	if "ciphertext is too short" != err.Error() {
		t.Errorf("Excepted '%v' to equal '%v'", err.Error(), "ciphertext is too short")
	}
}

func TestDESModeCBCDecryptReturnsCorrectErrorWhenNotMultipleOfBlock(t *testing.T) {
	cipher := NewDESCipher(ModeCBC)
	cipher.SetKey("kdsfjas;k@!$KFNMSDFMS")

	testText := []byte("test example string ¬¨ˆ¥®†§!@#$%^&*()")

	enc := cipher.Encrypt(testText)
	_, err := cipher.Decrypt(enc[1:])

	if "ciphertext is not a multiple of the block size" != err.Error() {
		t.Errorf("Excepted '%v' to equal '%v'", err.Error(), "ciphertext is not a multiple of the block size")
	}
}

func TestTripleDESCipherWithModeCBC(t *testing.T) {
	cipher := NewDESCipher(ModeCBC)
	cipher.SetKey("test example key!1")

	testCipher(t, cipher)
}

func TestTripleDESCipherWithModeCFB(t *testing.T) {
	cipher := NewTripleDESCipher(ModeCFB)
	cipher.SetKey("test example key!2")

	testCipher(t, cipher)
}

func TestTripleDESCipherWithModeCTR(t *testing.T) {
	cipher := NewTripleDESCipher(ModeCTR)
	cipher.SetKey("test example key!3")

	testCipher(t, cipher)
}

func TestTripleDESCipherWithModeOFB(t *testing.T) {
	cipher := NewTripleDESCipher(ModeOFB)
	cipher.SetKey("test example key!4")

	testCipher(t, cipher)
}

func TestTripleDESModeCBCDecryptReturnsCorrectErrorWhenTooShort(t *testing.T) {
	cipher := NewTripleDESCipher(ModeCBC)
	cipher.SetKey("kdsfjas;k@!$KFNMSDFMS")

	testText := []byte("test example string ¬¨ˆ¥®†§!@#$%^&*()")

	enc := cipher.Encrypt(testText)
	_, err := cipher.Decrypt(enc[1:2])

	if "ciphertext is too short" != err.Error() {
		t.Errorf("Excepted '%v' to equal '%v'", err.Error(), "ciphertext is too short")
	}
}

func TestTripleDESModeCBCDecryptReturnsCorrectErrorWhenNotMultipleOfBlock(t *testing.T) {
	cipher := NewTripleDESCipher(ModeCBC)
	cipher.SetKey("kdsfjas;k@!$KFNMSDFMS")

	testText := []byte("test example string ¬¨ˆ¥®†§!@#$%^&*()")

	enc := cipher.Encrypt(testText)
	_, err := cipher.Decrypt(enc[1:])

	if "ciphertext is not a multiple of the block size" != err.Error() {
		t.Errorf("Excepted '%v' to equal '%v'", err.Error(), "ciphertext is not a multiple of the block size")
	}
}
