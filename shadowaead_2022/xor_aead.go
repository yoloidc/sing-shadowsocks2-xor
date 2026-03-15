package shadowaead_2022

import "crypto/cipher"

type xorAEAD struct {
	key []byte
}

func newXorAEAD(key []byte) cipher.AEAD {
	k := make([]byte, len(key))
	copy(k, key)
	return &xorAEAD{key: k}
}

func (x *xorAEAD) NonceSize() int { return 0 }
func (x *xorAEAD) Overhead() int  { return 0 }

func (x *xorAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ret := append(dst, plaintext...)
	x.xorSlice(ret[len(dst):])
	return ret
}

func (x *xorAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	ret := append(dst, ciphertext...)
	x.xorSlice(ret[len(dst):])
	return ret, nil
}

func (x *xorAEAD) xorSlice(b []byte) {
	kl := len(x.key)
	if kl == 0 {
		return
	}
	for i := range b {
		b[i] ^= x.key[i%kl]
	}
}
