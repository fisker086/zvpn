package openconnect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (h *Handler) generatePasswordToken(username string) string {
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", username, timestamp)

	secret := h.config.JWT.Secret

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", message, signature)))
}

func (h *Handler) verifyPasswordToken(token string, username string) bool {
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	parts := strings.Split(string(data), ":")
	if len(parts) != 3 {
		return false
	}

	tokenUsername := parts[0]
	timestampStr := parts[1]
	signature := parts[2]

	if tokenUsername != username {
		return false
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-timestamp > 300 {
		return false
	}

	secret := h.config.JWT.Secret

	message := fmt.Sprintf("%s:%s", tokenUsername, timestampStr)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

