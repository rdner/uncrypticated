package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestRandomString(t *testing.T) {
	t.Run("does not repeat the same value twice", func(t *testing.T) {
		r1, err := RandomString(16)
		if err != nil {
			t.Fatal(err)
		}
		if len(r1) != 16 {
			t.Fatal("string length must be 15 characters")
		}

		r2, err := RandomString(16)
		if err != nil {
			t.Fatal(err)
		}
		if len(r2) != 16 {
			t.Fatal("string length must be 15 characters")
		}

		if r1 == r2 {
			t.Fatal("must produce different strings in a row")
		}
	})

	t.Run("supports lengths %2 != 0", func(t *testing.T) {
		r1, err := RandomString(15)
		if err != nil {
			t.Fatal(err)
		}
		if len(r1) != 15 {
			t.Fatal("string length must be 15 characters")
		}
	})
}

func TestPassphraseToKey(t *testing.T) {
	passphrase := "somekey"
	key := PassphraseToKey(passphrase)
	if len(key) != 32 {
		t.Fatal("the key length must be 32 bytes")
	}
	key2 := PassphraseToKey(passphrase)
	if !bytes.Equal(key, key2) {
		t.Fatal("`PassphraseToKey` must be determenistic and always return the same value for the same parameter")
	}
}

func Test_EncryptDecrypt(t *testing.T) {
	key := PassphraseToKey("some very secure passphrase no hacker can hack")
	text := []byte("some very secret text to encrypt")

	t.Run("encrypts/decrypts bytes", func(t *testing.T) {
		cipherText, err := Encrypt(text, key)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(text, cipherText) {
			t.Fatal("cipher text must differ the original text")
		}

		plainText, err := Decrypt(cipherText, key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(text, plainText) {
			t.Fatal("decrypted text must match the original text")
		}
	})

	t.Run("encrypts/decrypts a string", func(t *testing.T) {
		cipherTextString, err := EncryptToString(text, key)
		if err != nil {
			t.Fatal(err)
		}
		if string(text) == cipherTextString {
			t.Fatal("cipher text must differ the original text")
		}

		plainText, err := DecryptFromString(cipherTextString, key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(text, plainText) {
			t.Fatal("decrypted text must match the original text")
		}
	})

	t.Run("returns error if the cipher text is too short", func(t *testing.T) {
		_, err := Decrypt([]byte{0}, key)
		if err != ErrCipherTooShort {
			t.Fatal(err, "expected `ErrCipherTooShort`")
		}
	})
}

func Test_CreateValidateToken(t *testing.T) {
	id, _ := RandomString(16)
	key := PassphraseToKey("some very secure passphrase no hacker can hack")
	lifetime := 5 * time.Second

	token, err := CreateToken(key, id)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		token    string
		id       string
		lifetime time.Duration
		err      error
	}{
		{
			name:     "valid token",
			token:    token,
			id:       id,
			lifetime: lifetime,
		},
		{
			name:     "invalid token",
			token:    "wrong",
			id:       id,
			lifetime: lifetime,
			err:      ErrTokenInvalid,
		},
		{
			name:     "invalid ID",
			token:    token,
			id:       "wrong",
			lifetime: lifetime,
			err:      ErrTokenNoIDMatch,
		},
		{
			name:     "exceeds lifetime",
			token:    token,
			id:       id,
			lifetime: 5 * time.Millisecond,
			err:      ErrTokenExpired,
		},
	}

	time.Sleep(10 * time.Millisecond) // to check the lifetime case

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateToken(c.token, key, c.id, c.lifetime)
			if err != c.err {
				t.Fatalf("expected `%v`, got `%v`", c.err, err)
			}
		})
	}
}
