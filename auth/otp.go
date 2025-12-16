package auth

import (
	"crypto/rand"
	"encoding/base32"

	"github.com/pquerna/otp/totp"
)

// OTPAuthenticator OTP认证器
type OTPAuthenticator struct {
	issuer string
}

// NewOTPAuthenticator 创建OTP认证器
func NewOTPAuthenticator(issuer string) *OTPAuthenticator {
	return &OTPAuthenticator{
		issuer: issuer,
	}
}

// GenerateSecret 为用户生成OTP密钥
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

// ValidateOTP 验证OTP代码
func (o *OTPAuthenticator) ValidateOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateRecoveryCodes 生成恢复代码
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

