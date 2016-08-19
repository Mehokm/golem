package golem

import "crypto/aes"

// NewAES256Cipher returns a new AES256 block cipher set to a specific cipher mode
func NewAES256Cipher(mode cipherMode) Cipher {
	encryptor := aesEncryptor()
	encryptor.keylen = 32 // AES256

	return getCipher(mode, encryptor)
}

// NewAES192Cipher returns a new AES192 block cipher set to a specific cipher mode
func NewAES192Cipher(mode cipherMode) Cipher {
	encryptor := aesEncryptor()
	encryptor.keylen = 24 // AES192

	return getCipher(mode, encryptor)
}

// NewAES128Cipher returns a new AES128 block cipher set to a specific cipher mode
func NewAES128Cipher(mode cipherMode) Cipher {
	encryptor := aesEncryptor()
	encryptor.keylen = 16 // AES128

	return getCipher(mode, encryptor)
}

func aesEncryptor() *encryptor {
	return &encryptor{
		blockSize:  aes.BlockSize,
		cipherFunc: aes.NewCipher,
	}
}
