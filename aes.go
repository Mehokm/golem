package golem

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// AES Cipher Modes
const (
	ModeCBC cipherMode = 1 << iota
	ModeCFB
	ModeCTR
	ModeOFB
)

// AES Key Length Sizes
const (
	AES128 keySize = 16
	AES192 keySize = 24
	AES256 keySize = 32
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

type blockModeEncryption struct {
	*aesCipher
	encrypterFunc func(b cipher.Block, iv []byte) cipher.BlockMode
	decrypterFunc func(b cipher.Block, iv []byte) cipher.BlockMode
}

type streamEncryption struct {
	*aesCipher
	encrypterFunc func(b cipher.Block, iv []byte) cipher.Stream
	decrypterFunc func(b cipher.Block, iv []byte) cipher.Stream
}

type aesCipher struct {
	block  cipher.Block
	keylen keySize
}

// keySize wraps int type to enforce certain AES key sizes
type keySize int

// cipherMode wraps int type to enforce AES mode
type cipherMode int

// NewAESCipher returns a new AES block cipher set to a specific cipher mode
func NewAESCipher(mode cipherMode) Cipher {
	switch mode {
	case ModeCBC:
		return &blockModeEncryption{
			&aesCipher{
				keylen: AES128,
			},
			blockModeFuncMap[mode]["encrypt"],
			blockModeFuncMap[mode]["decrypt"],
		}
	case ModeCFB, ModeCTR, ModeOFB:
		return &streamEncryption{
			&aesCipher{
				keylen: AES128,
			},
			streamFuncMap[mode]["encrypt"],
			streamFuncMap[mode]["decrypt"],
		}
	default:
		panic("unsupported cipher mode")
	}
}

func (c *aesCipher) SetKeyLength(size keySize) {
	c.keylen = size
}

func (c *aesCipher) SetKey(key string) {
	keyHash := sha256.Sum256([]byte(key))

	block, _ := aes.NewCipher(keyHash[:c.keylen])

	c.block = block
}

func (c *blockModeEncryption) Encrypt(data []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	mode := c.encrypterFunc(c.block, iv)

	plaintextBlockRem := len(data) % aes.BlockSize
	if plaintextBlockRem != 0 {
		data = append(data, make([]byte, int(aes.BlockSize-plaintextBlockRem))...)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	ciphertext = append(iv, ciphertext[aes.BlockSize:]...)

	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext
}

func (c *blockModeEncryption) Decrypt(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext is too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := c.decrypterFunc(c.block, iv)

	plaintext := make([]byte, len(data)-aes.BlockSize)

	mode.CryptBlocks(plaintext, data[aes.BlockSize:])

	return bytes.Trim(plaintext, "\x00"), nil
}

func (c *streamEncryption) Encrypt(data []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	stream := c.encrypterFunc(c.block, iv)

	ciphertext := make([]byte, aes.BlockSize+len(data))
	ciphertext = append(iv, ciphertext[aes.BlockSize:]...)

	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext
}

func (c *streamEncryption) Decrypt(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext is too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := c.decrypterFunc(c.block, iv)

	plaintext := make([]byte, len(ciphertext))

	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
