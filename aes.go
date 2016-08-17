package golem

import "crypto/aes"

// Key Length Sizes
const (
	AES128 keySize = 16
	AES192 keySize = 24
	AES256 keySize = 32
)

// NewAESCipher returns a new AES block cipher set to a specific cipher mode
func NewAESCipher(mode cipherMode) Cipher {
	encryptor := &encryptor{}
	encryptor.keylen = AES128
	encryptor.blockSize = aes.BlockSize
	encryptor.cipherFunc = aes.NewCipher

	return getCipher(mode, encryptor)
}
