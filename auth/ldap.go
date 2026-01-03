package auth

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConfig struct {
	Enabled       bool
	Host          string
	Port          int
	UseSSL        bool
	BindDN        string
	BindPassword  string
	BaseDN        string
	UserFilter    string // 例如: (uid=%s) 或 (sAMAccountName=%s)
	AdminGroup    string // 管理员组 DN
	SkipTLSVerify bool

	AttributeMapping AttributeMapping
}

type AttributeMapping struct {
	UsernameAttribute string // 用户名属性，例如: "uid", "sAMAccountName", "cn"
	EmailAttribute    string // 邮箱属性，例如: "mail", "email"
	FullNameAttribute string // 全名属性，例如: "displayName", "cn", "name"
	MemberOfAttribute string // 组成员属性，例如: "memberOf", "groupMembership"
}

type LDAPAuthenticator struct {
	config *LDAPConfig
}

func NewLDAPAuthenticator(config *LDAPConfig) *LDAPAuthenticator {
	return &LDAPAuthenticator{
		config: config,
	}
}

func (l *LDAPAuthenticator) Authenticate(username, password string) (*LDAPUser, error) {
	if !l.config.Enabled {
		return nil, fmt.Errorf("LDAP is not enabled")
	}

	if l.config.Host == "" || l.config.BindDN == "" || l.config.BaseDN == "" || l.config.UserFilter == "" {
		return nil, fmt.Errorf("LDAP configuration is incomplete: Host, BindDN, BaseDN, and UserFilter are required")
	}

	if !strings.Contains(l.config.UserFilter, "%s") && !strings.Contains(l.config.UserFilter, "{0}") {
		return nil, fmt.Errorf("UserFilter must contain %%s or {0} placeholder, got: %s", l.config.UserFilter)
	}

	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	conn, err := l.connect()
	if err != nil {
		log.Printf("LDAP: Connection failed for user '%s' to %s:%d: %v", username, l.config.Host, l.config.Port, err)
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("LDAP: Warning - Error closing connection for user '%s': %v", username, err)
		}
	}()

	if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
		log.Printf("LDAP: Admin bind failed for user '%s': %v", username, err)
		return nil, fmt.Errorf("failed to bind with admin account: %w", err)
	}

	userDN, userInfo, err := l.searchUser(conn, username)
	if err != nil {
		log.Printf("LDAP: User search failed for username '%s' with filter '%s' in BaseDN '%s': %v",
			username, l.config.UserFilter, l.config.BaseDN, err)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	log.Printf("LDAP: Found user '%s' with DN: %s", username, userDN)

	if err := conn.Bind(userDN, password); err != nil {
		log.Printf("LDAP: Authentication failed for user '%s' (DN: %s): %v", username, userDN, err)
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	isAdmin := false
	if l.config.AdminGroup != "" {
		isAdmin, err = l.isUserInGroup(conn, userDN, l.config.AdminGroup)
		if err != nil {
			log.Printf("Warning: Failed to check admin group: %v", err)
		}
	}

	_, emailAttr, fullNameAttr, memberOfAttr := l.getAttributeMapping()

	searchRequest2 := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dn", "cn", emailAttr, fullNameAttr, memberOfAttr},
		nil,
	)

	result2, err := conn.Search(searchRequest2)
	var attributes map[string]interface{}

	if err == nil && len(result2.Entries) > 0 {
		entry2 := result2.Entries[0]
		attributes = normalizeLDAPAttributes(entry2.Attributes)
	}

	return &LDAPUser{
		DN:         userDN,
		Username:   username,
		Email:      userInfo.Email,
		FullName:   userInfo.FullName,
		IsAdmin:    isAdmin,
		Attributes: attributes,
	}, nil
}

func (l *LDAPAuthenticator) connect() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", l.config.Host, l.config.Port)

	var conn *ldap.Conn
	var err error

	if l.config.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: l.config.SkipTLSVerify,
			ServerName:         l.config.Host, // 设置 SNI，某些服务器需要
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to LDAPS server %s: %w", address, err)
		}
	} else {
		conn, err = ldap.Dial("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", address, err)
		}
	}

	conn.SetTimeout(10 * time.Second)

	return conn, nil
}

func (l *LDAPAuthenticator) searchUser(conn *ldap.Conn, username string) (string, *LDAPUserInfo, error) {
	escapedUsername := ldap.EscapeFilter(username)
	filter := l.config.UserFilter

	if strings.Contains(filter, "{0}") {
		filter = strings.ReplaceAll(filter, "{0}", escapedUsername)
	} else if strings.Contains(filter, "%s") {
		filter = fmt.Sprintf(filter, escapedUsername)
	} else {
		return "", nil, fmt.Errorf("user_filter format error: must contain %%s or {0} placeholder, got: %s", filter)
	}

	_, emailAttr, fullNameAttr, memberOfAttr := l.getAttributeMapping()

	searchRequest := ldap.NewSearchRequest(
		l.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"dn", "cn", emailAttr, fullNameAttr, memberOfAttr},
		nil,
	)

	log.Printf("LDAP: Searching user '%s' with filter '%s' in BaseDN '%s'", username, filter, l.config.BaseDN)
	result, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("LDAP: Search failed for user '%s': %v", username, err)
		return "", nil, err
	}

	if len(result.Entries) == 0 {
		log.Printf("LDAP: No user found matching filter '%s' in BaseDN '%s'", filter, l.config.BaseDN)
		return "", nil, fmt.Errorf("user not found")
	}

	if len(result.Entries) > 1 {
		log.Printf("LDAP: Multiple users found (%d) matching filter '%s':", len(result.Entries), filter)
		for i, entry := range result.Entries {
			log.Printf("LDAP:   [%d] DN: %s", i+1, entry.DN)
		}
		return "", nil, fmt.Errorf("multiple users found")
	}

	entry := result.Entries[0]

	email := entry.GetAttributeValue(emailAttr)
	fullName := entry.GetAttributeValue(fullNameAttr)
	if fullName == "" {
		fullName = entry.GetAttributeValue("cn")
	}

	userInfo := &LDAPUserInfo{
		Email:    email,
		FullName: fullName,
	}

	return entry.DN, userInfo, nil
}

func (l *LDAPAuthenticator) isUserInGroup(conn *ldap.Conn, userDN, groupDN string) (bool, error) {
	if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
		return false, err
	}

	_, _, _, memberOfAttr := l.getAttributeMapping()

	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{memberOfAttr},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return false, err
	}

	if len(result.Entries) == 0 {
		return false, nil
	}

	memberOfList := result.Entries[0].GetAttributeValues(memberOfAttr)
	for _, memberOf := range memberOfList {
		if memberOf == groupDN {
			return true, nil
		}
	}

	return false, nil
}

func (l *LDAPAuthenticator) inferUsernameAttributeFromFilter() string {
	filter := l.config.UserFilter
	if strings.Contains(filter, "uid=") {
		return "uid"
	}
	if strings.Contains(filter, "sAMAccountName=") {
		return "sAMAccountName"
	}
	if strings.Contains(filter, "cn=") {
		return "cn"
	}
	return ""
}

func (l *LDAPAuthenticator) getAttributeMapping() (usernameAttr, emailAttr, fullNameAttr, memberOfAttr string) {
	usernameAttr = l.config.AttributeMapping.UsernameAttribute
	if usernameAttr == "" {
		usernameAttr = l.inferUsernameAttributeFromFilter()
	}

	emailAttr = l.config.AttributeMapping.EmailAttribute
	if emailAttr == "" {
		emailAttr = "mail"
	}
	fullNameAttr = l.config.AttributeMapping.FullNameAttribute
	if fullNameAttr == "" {
		fullNameAttr = "displayName"
	}
	memberOfAttr = l.config.AttributeMapping.MemberOfAttribute
	if memberOfAttr == "" {
		memberOfAttr = "memberOf"
	}
	return
}

func (l *LDAPAuthenticator) extractUsernameFromEntry(entry *ldap.Entry, usernameAttr string) string {
	if usernameAttr != "" {
		if username := entry.GetAttributeValue(usernameAttr); username != "" {
			return username
		}
	}

	if strings.Contains(l.config.UserFilter, "uid=") {
		if username := entry.GetAttributeValue("uid"); username != "" {
			return username
		}
	} else if strings.Contains(l.config.UserFilter, "sAMAccountName=") {
		if username := entry.GetAttributeValue("sAMAccountName"); username != "" {
			return username
		}
	} else if strings.Contains(l.config.UserFilter, "cn=") {
		if username := entry.GetAttributeValue("cn"); username != "" {
			return username
		}
	}

	commonAttrs := []string{"uid", "sAMAccountName", "cn"}
	for _, attr := range commonAttrs {
		if username := entry.GetAttributeValue(attr); username != "" {
			return username
		}
	}

	dnParts := strings.Split(entry.DN, ",")
	if len(dnParts) > 0 {
		cnPart := strings.TrimSpace(dnParts[0])
		if strings.HasPrefix(cnPart, "cn=") {
			return strings.TrimPrefix(cnPart, "cn=")
		} else if strings.HasPrefix(cnPart, "uid=") {
			return strings.TrimPrefix(cnPart, "uid=")
		}
	}

	return ""
}

func normalizeLDAPAttributes(attrs []*ldap.EntryAttribute) map[string]interface{} {
	result := make(map[string]interface{})

	for _, attr := range attrs {
		if len(attr.Values) == 1 {
			result[attr.Name] = attr.Values[0]
		} else if len(attr.Values) > 1 {
			result[attr.Name] = attr.Values
		}
	}

	return result
}

type LDAPUser struct {
	DN         string                 // Distinguished Name
	Username   string                 // 用户名 (uid/sAMAccountName/cn)
	Email      string                 // 邮箱 (mail)
	FullName   string                 // 全名/中文名 (displayName/cn)
	IsAdmin    bool                   // 是否是管理员
	Attributes map[string]interface{} // LDAP原始属性（单值属性为字符串，多值属性为数组）
}

type LDAPUserInfo struct {
	Email    string
	FullName string
}

func (l *LDAPAuthenticator) SearchAllUsers() ([]*LDAPUser, error) {
	if !l.config.Enabled {
		return nil, fmt.Errorf("LDAP is not enabled")
	}

	if l.config.Host == "" || l.config.BindDN == "" || l.config.BaseDN == "" || l.config.UserFilter == "" {
		return nil, fmt.Errorf("LDAP configuration is incomplete: Host, BindDN, BaseDN, and UserFilter are required")
	}

	conn, err := l.connect()
	if err != nil {
		log.Printf("LDAP: Connection failed for SearchAllUsers: %v", err)
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("LDAP: Warning - Error closing connection for SearchAllUsers: %v", err)
		}
	}()

	if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
		log.Printf("LDAP: Admin bind failed for SearchAllUsers: %v", err)
		return nil, fmt.Errorf("failed to bind with admin account: %w", err)
	}

	baseFilter := l.config.UserFilter
	if strings.Contains(baseFilter, "{0}") {
		baseFilter = strings.ReplaceAll(baseFilter, "{0}", "*")
	} else if strings.Contains(baseFilter, "%s") {
		baseFilter = strings.ReplaceAll(baseFilter, "%s", "*")
	} else {
	}

	usernameAttr, emailAttr, fullNameAttr, memberOfAttr := l.getAttributeMapping()

	attributes := []string{"dn", "cn", emailAttr, fullNameAttr, memberOfAttr}
	if usernameAttr != "" {
		attributes = append(attributes, usernameAttr)
	}
	attributes = append(attributes, "uid", "sAMAccountName")

	searchRequest := ldap.NewSearchRequest(
		l.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		baseFilter,
		attributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP users: %w", err)
	}

	var users []*LDAPUser
	for _, entry := range result.Entries {
		username := l.extractUsernameFromEntry(entry, usernameAttr)
		if username == "" {
			continue
		}

		isAdmin := false
		if l.config.AdminGroup != "" {
			memberOfList := entry.GetAttributeValues(memberOfAttr)
			for _, memberOf := range memberOfList {
				if memberOf == l.config.AdminGroup {
					isAdmin = true
					break
				}
			}
		}

		email := entry.GetAttributeValue(emailAttr)
		fullName := entry.GetAttributeValue(fullNameAttr)
		if fullName == "" {
			fullName = entry.GetAttributeValue("cn")
		}

		attributes := normalizeLDAPAttributes(entry.Attributes)

		users = append(users, &LDAPUser{
			DN:         entry.DN,
			Username:   username,
			Email:      email,
			FullName:   fullName,
			IsAdmin:    isAdmin,
			Attributes: attributes,
		})
	}

	return users, nil
}
