package openconnect

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func (h *Handler) setAnyConnectResponseHeaders(c *gin.Context) {
	c.Writer.Header().Del("Server")
	c.Writer.Header().Del("X-Powered-By")

	c.Header("X-CSTP-Version", "1")
	c.Header("X-Transcend-Version", "1")
	c.Header("X-Aggregate-Auth", "1")

	if connHeader := c.GetHeader("Connection"); connHeader != "" {
		c.Header("Connection", connHeader)
	} else {
		c.Header("Connection", "Keep-Alive")
	}

	c.Header("Cache-Control", "no-cache")
	c.Header("Pragma", "no-cache")
}

func (h *Handler) sendAuthForm(c *gin.Context) {
	select {
	case <-c.Request.Context().Done():
		return
	default:
	}

	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <version who="sg">9.12(4)13</version>
    <title>Secure Gateway</title>
    <auth id="main">
        <message>Authorized users only. All activity may be monitored.</message>
        <form>
            <input type="text" name="username" label="Username:"></input>
            <input type="password" name="password" label="Password:"></input>
        </form>
    </auth>
</config-auth>`

	h.setAnyConnectResponseHeaders(c)
	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xmlContent)))

	select {
	case <-c.Request.Context().Done():
		return
	default:
	}

	defer func() {
		if r := recover(); r != nil {
			log.Printf("OpenConnect: sendAuthForm panic: %v", r)
		}
	}()

	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xmlContent))

	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (h *Handler) buildAuthRequestXML(c *gin.Context, authContent, tunnelGroup, groupAlias, aggauthHandle, configHash string) string {
	if aggauthHandle == "" {
		aggauthHandle = "168179266"
	}
	if configHash == "" {
		configHash = "1595829378234"
	}
	if tunnelGroup == "" {
		tunnelGroup = "default"
	}
	if groupAlias == "" {
		groupAlias = "default"
	}

	xml := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	xml += "<config-auth client=\"vpn\" type=\"auth-request\" aggregate-auth-version=\"2\">\n"
	xml += "    <opaque is-for=\"sg\">\n"
	xml += "        <tunnel-group>" + tunnelGroup + "</tunnel-group>\n"
	xml += "        <group-alias>" + groupAlias + "</group-alias>\n"
	xml += "        <aggauth-handle>" + aggauthHandle + "</aggauth-handle>\n"
	xml += "        <config-hash>" + configHash + "</config-hash>\n"
	xml += "        <auth-method>password</auth-method>\n"
	xml += "    </opaque>\n"
	xml += authContent

	xml += "</config-auth>"

	return xml
}

func (h *Handler) sendAuthRequestResponse(c *gin.Context, xmlContent string) {
	h.setAnyConnectResponseHeaders(c)
	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xmlContent)))

	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xmlContent))
}

func (h *Handler) sendAuthError(c *gin.Context, message string) {
	authContent := "    <auth id=\"main\">\n"
	authContent += "        <title>Authentication Failed</title>\n"
	authContent += "        <message>" + message + "</message>\n"
	authContent += "        <banner></banner>\n"
	authContent += "        <form method=\"post\" action=\"/\">\n"
	authContent += "            <input type=\"text\" name=\"username\" label=\"Username:\" />\n"
	authContent += "            <input type=\"password\" name=\"password\" label=\"Password:\" />\n"
	authContent += "        </form>\n"
	authContent += "    </auth>\n"

	xml := h.buildAuthRequestXML(c, authContent, "default", "default", "", "")

	h.sendAuthRequestResponse(c, xml)
}

