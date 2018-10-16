package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

var (
	// ErrTokenInvalid occurs when `ValidateToken` failed to decode the token
	ErrTokenInvalid = errors.New("crypto: invalid token, failed to decode")
	// ErrTokenExpired occurs when `ValidateToken` succeeded
	// to decode the token but it's expired
	ErrTokenExpired = errors.New("crypto: token expired")
	// ErrTokenNoIDMatch occurs when `ValidateToken` succeeded
	// to decode the token but its ID does not match the validation request
	ErrTokenNoIDMatch = errors.New("crypto: token ID does not match")
	// ErrCipherTooShort occurs when `Decrypt` does not
	// have input of enough length to decrypt using AES256
	ErrCipherTooShort = errors.New("crypto: cipher plainText is too short for AES encryption")
)

type tokenClaims struct {
	// ID is an identifier used for token validation.
	// This can be a user ID, email, form ID (in case of CSRF), URL, etc.
	ID string `json:"id"`
	// Nonce is a randomly-generated string which is supposed
	// to increase entropy of the encrypted token
	Nonce string `json:"nonce"`
	// Timestamp is Unix timestamp when the token was created
	Timestamp int64 `json:"timestamp"`
}

// RandomString generates a random string of the specified length
func RandomString(length int) (string, error) {
	size := length
	// we generate bytes and it's 2 char per byte in a string
	// so we have to generate more and then trim
	if size%2 != 0 {
		size++
	}
	bytes := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	string := hex.EncodeToString(bytes)
	if len(string) > length {
		string = string[0:length]
	}
	return string, nil
}

// PassphraseToKey converts a string to a key for encryption
func PassphraseToKey(passphrase string) (key []byte) {
	// SHA512/256 will return exactly 32 bytes which is
	// the length of the key needed for AES256 encryption
	hash := sha512.Sum512_256([]byte(passphrase))
	return hash[:]
}

// Encrypt encrypts content with a key using AES256
func Encrypt(plainText, key []byte) (encrypted []byte, err error) {
	// code is taken from here https://golang.org/pkg/crypto/cipher/#NewCFBEncrypter
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
}

// EncryptToString encrypts content with a key using AES256
// and encodes it to a hexadecimal string
func EncryptToString(plainText, key []byte) (string, error) {
	bytes, err := Encrypt(plainText, key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Decrypt decrypts content with a key using AES256
func Decrypt(cipherText, key []byte) (decrypted []byte, err error) {
	// code is taken from here https://golang.org/pkg/crypto/cipher/#NewCFBDecrypter
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText) < aes.BlockSize {
		return nil, ErrCipherTooShort
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)

	return plainText, nil
}

// DecryptFromString decrypts a string with a key
func DecryptFromString(cipherTextStr string, key []byte) (decrypted []byte, err error) {
	cipherText, err := hex.DecodeString(cipherTextStr)
	if err != nil {
		return nil, err
	}
	return Decrypt(cipherText, key)
}

// CreateToken creates an encrypted token that can be validated later.
// `id` parameter can be any identifier and it's used to validate
// the token source later in the `ValidateToken` function.
// It can be an email, user ID, form name (for CSRF tokens), etc.
func CreateToken(key []byte, id string) (token string, err error) {
	nonce, err := RandomString(16)
	if err != nil {
		return "", err
	}
	claims := tokenClaims{
		ID:        id,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}
	bytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	token, err = EncryptToString(bytes, key)
	if err != nil {
		return "", err
	}
	return token, nil
}

// ValidateToken validates the encrypted token.
// `id` must be a string which was used in `CreateToken` earlier
func ValidateToken(token string, key []byte, id string, lifetime time.Duration) error {
	// We assume if we are able to decrypt the state string and it's possible
	// to parse JSON from the decrypted text it's an authentic token
	decrypted, err := DecryptFromString(token, key)
	if err != nil {
		return ErrTokenInvalid
	}
	var claims tokenClaims
	err = json.Unmarshal(decrypted, &claims)
	if err != nil {
		return ErrTokenInvalid
	}

	if claims.ID != id {
		return ErrTokenNoIDMatch
	}

	t := time.Unix(claims.Timestamp, 0)
	if t.Add(lifetime).Before(time.Now()) {
		return ErrTokenExpired
	}
	return nil
}
