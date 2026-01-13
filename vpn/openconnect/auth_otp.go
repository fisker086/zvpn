package openconnect

import (
	"encoding/base64"
	"image"
	"image/png"
	"log"
	"strings"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

func (h *Handler) sendOTPRequest(c *gin.Context, username string, errorMessage string) {
	passwordToken := h.generatePasswordToken(username)

	message := "Password verified. Please enter your OTP code from your authenticator app."
	if errorMessage != "" {
		message = errorMessage
	}

	// 检测客户端类型
	clientType := detectClientType(c)
	isOpenConnectClient := clientType == ClientTypeOpenConnect

	authContent := "    <auth id=\"otp-verification\">\n"
	authContent += "        <title>OTP 动态码验证</title>\n"
	authContent += "        <message>" + message + "</message>\n"
	if errorMessage != "" {
		authContent += "        <error id=\"otp-verification\" param1=\"" + errorMessage + "\" param2=\"\">验证失败:  %s</error>\n"
	}
	authContent += "        <form method=\"post\" action=\"/\">\n"
	authContent += "            <input type=\"hidden\" name=\"username\" value=\"" + username + "\" />\n"
	authContent += "            <input type=\"hidden\" name=\"password-token\" value=\"" + passwordToken + "\" />\n"

	// 为了兼容性，根据客户端类型使用不同的字段名
	// AnyConnect 使用 secondary_password（标准字段），OpenConnect 使用 otp-code
	// 服务器端解析时会优先读取 secondary_password，如果没有则读取 otp-code（已实现兼容）
	if isOpenConnectClient {
		// OpenConnect 客户端：使用 otp-code 字段
		authContent += "            <input type=\"password\" name=\"otp-code\" label=\"OTP Code (6 digits):\" />\n"
	} else {
		// AnyConnect 客户端：使用 secondary_password 字段（标准字段）
		authContent += "            <input type=\"password\" name=\"secondary_password\" label=\"OTPCode:\" />\n"
	}
	authContent += "        </form>\n"
	authContent += "    </auth>\n"

	xml := h.buildAuthRequestXML(c, authContent, "default", "default", "", "")

	h.sendAuthRequestResponse(c, xml)
}

func (h *Handler) sendOTPSetupRequest(c *gin.Context, username string) {
	passwordToken := h.generatePasswordToken(username)

	var user models.User
	if err := database.DB.Where("username = ?", username).First(&user).Error; err != nil {
		log.Printf("OpenConnect: Failed to find user %s for OTP setup", username)
		h.sendAuthError(c, "User not found")
		return
	}

	var secret string
	var key interface {
		Secret() string
		Image(width, height int) (image.Image, error)
	}
	var err error

	if user.OTPSecret != "" {
		key, err = totp.Generate(totp.GenerateOpts{
			Issuer:      "ZVPN",
			AccountName: user.Username,
		})
		if err != nil {
			log.Printf("OpenConnect: Failed to generate OTP key for user %s: %v", username, err)
			h.sendAuthError(c, "Failed to generate OTP key")
			return
		}
		secret = user.OTPSecret
	} else {
		key, err = totp.Generate(totp.GenerateOpts{
			Issuer:      "ZVPN",
			AccountName: user.Username,
		})
		if err != nil {
			log.Printf("OpenConnect: Failed to generate OTP key for user %s: %v", username, err)
			h.sendAuthError(c, "Failed to generate OTP key")
			return
		}
		secret = key.Secret()
	}

	img, err := key.Image(200, 200)
	if err != nil {
		log.Printf("OpenConnect: Failed to generate QR code for user %s: %v", username, err)
		h.sendAuthError(c, "Failed to generate QR code")
		return
	}

	var buf strings.Builder
	buf.WriteString("data:image/png;base64,")
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	if err := png.Encode(encoder, img); err != nil {
		log.Printf("OpenConnect: Failed to encode QR code for user %s: %v", username, err)
		h.sendAuthError(c, "Failed to encode QR code")
		return
	}
	encoder.Close()
	qrCode := buf.String()

	user.OTPSecret = secret
	if err := database.DB.Save(&user).Error; err != nil {
		log.Printf("OpenConnect: Failed to save OTP secret for user %s: %v", username, err)
		h.sendAuthError(c, "Failed to save OTP secret")
		return
	}

	message := "Please scan the QR code with your authenticator app (e.g., Google Authenticator), then enter the OTP code to complete setup."

	authContent := "    <auth id=\"otp-setup\">\n"
	authContent += "        <title>OTP Setup Required</title>\n"
	authContent += "        <message>" + message + "</message>\n"
	authContent += "        <banner>Scan this QR code with your authenticator app:</banner>\n"
	authContent += "        <img src=\"" + qrCode + "\" alt=\"OTP QR Code\" style=\"max-width: 200px; display: block; margin: 10px auto;\" />\n"
	authContent += "        <form method=\"post\" action=\"/\">\n"
	authContent += "            <input type=\"hidden\" name=\"username\" value=\"" + username + "\" />\n"
	authContent += "            <input type=\"hidden\" name=\"password-token\" value=\"" + passwordToken + "\" />\n"
	authContent += "            <input type=\"hidden\" name=\"otp-setup\" value=\"true\" />\n"
	authContent += "            <input type=\"text\" name=\"otp-code\" label=\"OTP Code (6 digits):\" />\n"
	authContent += "        </form>\n"
	authContent += "    </auth>\n"

	xml := h.buildAuthRequestXML(c, authContent, "default", "default", "", "")

	h.sendAuthRequestResponse(c, xml)
}

