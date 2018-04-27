package project

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
)

func makeKey() ([]byte, error) {
	// We won't be cryptographically secure in this toy project,
	// because crypto/rand is more annoying to use. In fact, we
	// won't even seed the global RNG! :)
	key := make([]byte, 32)
	if n, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("rand error: %s", err)
	} else if n != 32 {
		return nil, fmt.Errorf("couldn't read 32 random bytes for an unknown reason")
	}

	return key, nil
}

// This padding probably does not adhere to the AES standard.
func padData(rawData []byte) []byte {
	needPadding := aes.BlockSize - ((len(rawData) + 2) % aes.BlockSize)

	var dataBuf bytes.Buffer
	dataBuf.Grow(2 + len(rawData) + (aes.BlockSize % (len(rawData) + 2)))

	dataBuf.Write([]byte("|"))
	dataBuf.Write(rawData)
	dataBuf.Write([]byte("|"))

	for i := 0; i < needPadding; i++ {
		dataBuf.Write([]byte(" "))
	}

	return dataBuf.Bytes()
}

func encrypt(rawData []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key length should be exactly 32 bytes (we're using AES-256), but got %d", len(key))
	}

	data := padData(rawData)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher error: %s", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("error making IV: %s", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher error: %s", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext smaller than AES block size; did you pad correctly?")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the AES block size; did you pad correctly?")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove our padding (we'll just assume it was padded correctly,
	// but you could do a regex to check)
	ciphertext = bytes.TrimSpace(ciphertext)
	ciphertext = ciphertext[1 : len(ciphertext)-1]

	return ciphertext, nil
}

func marshalPrivateKey(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

func unmarshalPrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(keyBytes)
}

func marshalPublicKey(key *rsa.PublicKey) []byte {
	return x509.MarshalPKCS1PublicKey(key)
}

func unmarshalPublicKey(keyBytes []byte) (*rsa.PublicKey, error) {
	return x509.ParsePKCS1PublicKey(keyBytes)
}

func makeRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, RSA_KEY_BITS)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating keys: %s", err)
	}

	return private, &private.PublicKey, nil
}

func encryptRSA(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {
	out, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA encryption error: %s", err)
	}

	return out, nil
}

func decryptRSA(ciphertext []byte, key *rsa.PrivateKey) ([]byte, error) {
	out, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decryption error: %s", err)
	}

	return out, nil
}
