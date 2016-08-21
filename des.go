package golem

import "crypto/des"

// NewDESCipher returns a new DES block cipher set to a specific cipher mode
func NewDESCipher(mode cipherMode) Cipher {
	encryptor := &encryptor{
		keylen:     8, // DES56
		blockSize:  des.BlockSize,
		cipherFunc: des.NewCipher,
	}

	return getCipher(mode, encryptor)
}

// NewTripleDESCipher returns a new Triple DES block cipher set to a specific cipher mode
func NewTripleDESCipher(mode cipherMode) Cipher {
	encryptor := &encryptor{
		keylen:     24, // DES192
		blockSize:  des.BlockSize,
		cipherFunc: des.NewTripleDESCipher,
	}

	return getCipher(mode, encryptor)
}
