package auth

import (
	"crypto/rand"
	"encoding/base32"

	"github.com/pquerna/otp/totp"
)

type OTPAuthenticator struct {
	issuer string
}

func NewOTPAuthenticator(issuer string) *OTPAuthenticator {
	return &OTPAuthenticator{
		issuer: issuer,
	}
}

func (o *OTPAuthenticator) GenerateSecret(username string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      o.issuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}

	return key.Secret(), key.URL(), nil
}

func (o *OTPAuthenticator) ValidateOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

func (o *OTPAuthenticator) GenerateRecoveryCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		codes[i] = base32.StdEncoding.EncodeToString(bytes)
	}
	return codes, nil
}

