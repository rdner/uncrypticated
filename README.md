# uncrypticated - cryptography in Go made easy as it should be

No dependencies. Small and reliable.

## Features

### Encrypt/Decrypt bytes
```go
key := PassphraseToKey("some very secure passphrase no hacker can hack")
plainText := []byte("some very secret text to encrypt")
cipherText, err := Encrypt(text, key) // encryption done

// to decrypt back
plainText, err := Decrypt(cipherText, key)
```

### Encrypt/Decrypt strings
```go
key := PassphraseToKey("some very secure passphrase no hacker can hack")
plainText := []byte("some very secret text to encrypt")
cipherText, err := EncryptToString(text, key) // encryption done

// to decrypt back
plainText, err := DecryptFromString(cipherText, key)
```

### Generate random string with a given length
```go
randomString, err := RandomString(16)
```

### Generate/Validate an [encrypted token](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet#Encryption_based_Token_Pattern)
```go
id := "some user ID or basically any ID you can use"
key := PassphraseToKey("some very secure passphrase no hacker can hack")
token, err := CreateToken(key, id)

// then you can send this token to a user, or publish anywhere
// and of course you can validate it when you get it back
lifetime := 5 * time.Minute // let's say the token is valid for 5 minutes
err := ValidateToken(token, key, id, lifetime)
```

Can return following errors:
```go
var (
	// ErrTokenInvalid occurs when `ValidateToken` failed to decode the token
	ErrTokenInvalid = errors.New("crypto: invalid token, failed to decode")
	// ErrTokenExpired occurs when `ValidateToken` succeeded
	// to decode the token but it's expired
	ErrTokenExpired = errors.New("crypto: token expired")
	// ErrTokenNoIDMatch occurs when `ValidateToken` succeeded
	// to decode the token but its ID does not match the validation request
	ErrTokenNoIDMatch = errors.New("crypto: token ID does not match")
)
```

MIT License

Denis Rechkunov <mail@pragmader.me>
