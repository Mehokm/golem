package golem

// Cipher is an interface for all encryption ciphers
type Cipher interface {
	SetKeyLength(keySize)
	SetKey(string)
	Encrypt([]byte) []byte
	Decrypt([]byte) ([]byte, error)
}
