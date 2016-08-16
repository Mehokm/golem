package golem

import "crypto/cipher"

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

// keySize wraps int type to enforce certain AES key sizes
type keySize int

// cipherMode wraps int type to enforce AES mode
type cipherMode int

type encryptor struct {
	block  cipher.Block
	keylen keySize
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
		&encryptor{},
		blockModeFuncMap[mode]["encrypt"],
		blockModeFuncMap[mode]["decrypt"],
	}
}

func newSteamEncryption(mode cipherMode) streamEncryption {
	return streamEncryption{
		&encryptor{},
		streamFuncMap[mode]["encrypt"],
		streamFuncMap[mode]["decrypt"],
	}
}

// Cipher is an interface for all encryption ciphers
type Cipher interface {
	SetKeyLength(keySize)
	SetKey(string)
	Encrypt([]byte) []byte
	Decrypt([]byte) ([]byte, error)
}