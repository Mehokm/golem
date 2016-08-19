package golem

import (
	"bytes"
	"testing"
)

func TestRc4Encryption(t *testing.T) {
	r := NewRc4Cipher()
	r.SetKey("this is a test key. whoop de doo. 1239084908903849209348")

	testText := []byte("test example string ¬¨ˆ¥®†§!@#$%^&*()")

	enc := r.Encrypt(testText)
	dec, _ := r.Decrypt(enc)

	if bytes.Compare(testText, dec) != 0 {
		t.Errorf("decrypted text does not match test text: %v, %v", string(testText), string(dec))
	}
}
