package golem

import "crypto/des"

// NewDESCipher returns a new DES block cipher set to a specific cipher mode
func NewDESCipher(mode cipherMode) Cipher {
	encryptor := &encryptor{}
	encryptor.keylen = 8 // DES56
	encryptor.blockSize = des.BlockSize
	encryptor.cipherFunc = des.NewCipher

	return getCipher(mode, encryptor)
}

// NewTripleDESCipher returns a new Triple DES block cipher set to a specific cipher mode
func NewTripleDESCipher(mode cipherMode) Cipher {
	encryptor := &encryptor{}
	encryptor.keylen = 24 // DES192
	encryptor.blockSize = des.BlockSize
	encryptor.cipherFunc = des.NewTripleDESCipher

	return getCipher(mode, encryptor)
}
