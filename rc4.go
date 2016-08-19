package golem

import "crypto/rc4"

type rc4ModeEcnryption struct {
	key    []byte
	cipher *rc4.Cipher
}

// NewRc4Cipher returns a new rc4 cipher
func NewRc4Cipher() Cipher {
	return &rc4ModeEcnryption{}
}

func (r *rc4ModeEcnryption) SetKey(key string) error {
	keylen := len([]byte(key))

	if keylen < 1 || keylen > 256 {
		return rc4.KeySizeError(keylen)
	}

	r.key = []byte(key)

	return nil
}

func (r *rc4ModeEcnryption) Encrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))

	c, _ := rc4.NewCipher(r.key)
	c.XORKeyStream(encrypted, data)

	c.Reset()

	return encrypted
}

func (r *rc4ModeEcnryption) Decrypt(data []byte) ([]byte, error) {
	decrypted := make([]byte, len(data))

	c, _ := rc4.NewCipher(r.key)
	c.XORKeyStream(decrypted, data)

	c.Reset()

	return decrypted, nil
}
