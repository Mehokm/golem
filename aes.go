package golem

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// Key Length Sizes
const (
	AES128 keySize = 16
	AES192 keySize = 24
	AES256 keySize = 32
)

type aesBlockEncryption struct {
	blockModeEncryption
}

type aesStreamEncryption struct {
	streamEncryption
}

type aesEncryptor struct {
	*encryptor
}

// NewAESCipher returns a new AES block cipher set to a specific cipher mode
func NewAESCipher(mode cipherMode) Cipher {
	encryptor := aesEncryptor{&encryptor{}}
	encryptor.keylen = AES128

	switch mode {
	case ModeCBC:
		be := newBlockModeEncryption(mode)
		be.Keyer = encryptor
		return aesBlockEncryption{be}
	case ModeCFB, ModeCTR, ModeOFB:
		se := newSteamEncryption(mode)
		se.Keyer = encryptor
		return aesStreamEncryption{se}
	default:
		panic("unsupported cipher mode")
	}
}

func (e aesEncryptor) SetKeyLength(size keySize) {
	e.keylen = size
}

func (e aesEncryptor) SetKey(key string) {
	keyHash := sha256.Sum256([]byte(key))

	block, _ := aes.NewCipher(keyHash[:e.keylen])

	e.block = block
}

func (e aesEncryptor) GetBlock() cipher.Block {
	return e.block
}

func (a aesBlockEncryption) Encrypt(data []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	mode := a.encrypterFunc(a.GetBlock(), iv)

	plaintextBlockRem := len(data) % aes.BlockSize
	if plaintextBlockRem != 0 {
		data = append(data, make([]byte, int(aes.BlockSize-plaintextBlockRem))...)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	ciphertext = append(iv, ciphertext[aes.BlockSize:]...)

	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext
}

func (a aesBlockEncryption) Decrypt(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext is too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := a.decrypterFunc(a.GetBlock(), iv)

	plaintext := make([]byte, len(data)-aes.BlockSize)

	mode.CryptBlocks(plaintext, data[aes.BlockSize:])

	return bytes.Trim(plaintext, "\x00"), nil
}

func (a aesStreamEncryption) Encrypt(data []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	stream := a.encrypterFunc(a.GetBlock(), iv)

	ciphertext := make([]byte, aes.BlockSize+len(data))
	ciphertext = append(iv, ciphertext[aes.BlockSize:]...)

	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext
}

func (a aesStreamEncryption) Decrypt(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext is too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := a.decrypterFunc(a.GetBlock(), iv)

	plaintext := make([]byte, len(ciphertext))

	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
