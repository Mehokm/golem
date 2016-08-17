package golem

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// Cipher Modes
const (
	ModeCBC cipherMode = 1 << iota
	ModeCFB
	ModeCTR
	ModeOFB
)

var (
	blockModeFuncMap = map[cipherMode]map[string]func(b cipher.Block, iv []byte) cipher.BlockMode{
		ModeCBC: map[string]func(b cipher.Block, iv []byte) cipher.BlockMode{
			"encrypt": cipher.NewCBCEncrypter,
			"decrypt": cipher.NewCBCDecrypter,
		},
	}

	streamFuncMap = map[cipherMode]map[string]func(b cipher.Block, iv []byte) cipher.Stream{
		ModeCFB: map[string]func(b cipher.Block, iv []byte) cipher.Stream{
			"encrypt": cipher.NewCFBEncrypter,
			"decrypt": cipher.NewCFBDecrypter,
		},
		ModeCTR: map[string]func(b cipher.Block, iv []byte) cipher.Stream{
			"encrypt": cipher.NewCTR,
			"decrypt": cipher.NewCTR,
		},
		ModeOFB: map[string]func(b cipher.Block, iv []byte) cipher.Stream{
			"encrypt": cipher.NewOFB,
			"decrypt": cipher.NewOFB,
		},
	}
)

// Cipher is an interface for all encryption ciphers
type Cipher interface {
	SetKeyLength(keySize)
	SetKey(string) error
	Encrypt([]byte) []byte
	Decrypt([]byte) ([]byte, error)
}

// keySize wraps int type to enforce certain AES key sizes
type keySize int

// cipherMode wraps int type to enforce AES mode
type cipherMode int

type encryptor struct {
	cipherFunc func([]byte) (cipher.Block, error)
	blockSize  int
	block      cipher.Block
	keylen     keySize
}

type blockModeEncryption struct {
	*encryptor
	encrypterFunc func(b cipher.Block, iv []byte) cipher.BlockMode
	decrypterFunc func(b cipher.Block, iv []byte) cipher.BlockMode
}

type streamEncryption struct {
	*encryptor
	encrypterFunc func(b cipher.Block, iv []byte) cipher.Stream
	decrypterFunc func(b cipher.Block, iv []byte) cipher.Stream
}

func newBlockModeEncryption(mode cipherMode) blockModeEncryption {
	return blockModeEncryption{
		encryptor:     &encryptor{},
		encrypterFunc: blockModeFuncMap[mode]["encrypt"],
		decrypterFunc: blockModeFuncMap[mode]["decrypt"],
	}
}

func newSteamEncryption(mode cipherMode) streamEncryption {
	return streamEncryption{
		encryptor:     &encryptor{},
		encrypterFunc: streamFuncMap[mode]["encrypt"],
		decrypterFunc: streamFuncMap[mode]["decrypt"],
	}
}

func getCipher(mode cipherMode, encryptor *encryptor) Cipher {
	switch mode {
	case ModeCBC:
		be := newBlockModeEncryption(mode)
		be.encryptor = encryptor
		return be
	case ModeCFB, ModeCTR, ModeOFB:
		se := newSteamEncryption(mode)
		se.encryptor = encryptor
		return se
	default:
		panic("unsupported cipher mode")
	}
}

func (e *encryptor) SetKeyLength(size keySize) {
	e.keylen = size
}

func (e *encryptor) SetKey(key string) error {
	keyHash := sha256.Sum256([]byte(key))

	block, err := e.cipherFunc(keyHash[:e.keylen])

	e.block = block

	return err
}

func (a blockModeEncryption) Encrypt(data []byte) []byte {
	iv := make([]byte, a.blockSize)
	rand.Read(iv)

	mode := a.encrypterFunc(a.block, iv)

	plaintextBlockRem := len(data) % a.blockSize
	if plaintextBlockRem != 0 {
		data = append(data, make([]byte, int(a.blockSize-plaintextBlockRem))...)
	}

	ciphertext := make([]byte, a.blockSize+len(data))
	ciphertext = append(iv, ciphertext[a.blockSize:]...)

	mode.CryptBlocks(ciphertext[a.blockSize:], data)

	return ciphertext
}

func (a blockModeEncryption) Decrypt(data []byte) ([]byte, error) {
	if len(data) < a.blockSize {
		return nil, errors.New("ciphertext is too short")
	}

	iv := data[:a.blockSize]
	ciphertext := data[a.blockSize:]

	if len(ciphertext)%a.blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := a.decrypterFunc(a.block, iv)

	plaintext := make([]byte, len(data)-a.blockSize)

	mode.CryptBlocks(plaintext, data[a.blockSize:])

	return bytes.Trim(plaintext, "\x00"), nil
}

func (a streamEncryption) Encrypt(data []byte) []byte {
	iv := make([]byte, a.blockSize)
	rand.Read(iv)

	stream := a.encrypterFunc(a.block, iv)

	ciphertext := make([]byte, a.blockSize+len(data))
	ciphertext = append(iv, ciphertext[a.blockSize:]...)

	stream.XORKeyStream(ciphertext[a.blockSize:], data)

	return ciphertext
}

func (a streamEncryption) Decrypt(data []byte) ([]byte, error) {
	if len(data) < a.blockSize {
		return nil, errors.New("ciphertext is too short")
	}

	iv := data[:a.blockSize]
	ciphertext := data[a.blockSize:]

	stream := a.decrypterFunc(a.block, iv)

	plaintext := make([]byte, len(ciphertext))

	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
