package auth

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig LDAP 配置
type LDAPConfig struct {
	Enabled        bool
	Host           string
	Port           int
	UseSSL         bool
	BindDN         string
	BindPassword   string
	BaseDN         string
	UserFilter     string // 例如: (uid=%s) 或 (sAMAccountName=%s)
	AdminGroup     string // 管理员组 DN
	SkipTLSVerify  bool
}

// LDAPAuthenticator LDAP 认证器
type LDAPAuthenticator struct {
	config *LDAPConfig
}

// NewLDAPAuthenticator 创建 LDAP 认证器
func NewLDAPAuthenticator(config *LDAPConfig) *LDAPAuthenticator {
	return &LDAPAuthenticator{
		config: config,
	}
}

// Authenticate LDAP 认证
func (l *LDAPAuthenticator) Authenticate(username, password string) (*LDAPUser, error) {
	if !l.config.Enabled {
		return nil, fmt.Errorf("LDAP is not enabled")
	}

	// 连接 LDAP 服务器
	conn, err := l.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	// 使用管理员账号绑定
	if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
		return nil, fmt.Errorf("failed to bind with admin account: %w", err)
	}

	// 搜索用户
	userDN, userInfo, err := l.searchUser(conn, username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// 使用用户凭据验证
	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	// 检查用户是否是管理员
	isAdmin := false
	if l.config.AdminGroup != "" {
		isAdmin, err = l.isUserInGroup(conn, userDN, l.config.AdminGroup)
		if err != nil {
			// 管理员组检查失败不影响登录，只记录日志
			fmt.Printf("Warning: Failed to check admin group: %v\n", err)
		}
	}

	return &LDAPUser{
		DN:       userDN,
		Username: username,
		Email:    userInfo.Email,
		FullName: userInfo.FullName,
		IsAdmin:  isAdmin,
	}, nil
}

// connect 连接到 LDAP 服务器
func (l *LDAPAuthenticator) connect() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", l.config.Host, l.config.Port)

	if l.config.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: l.config.SkipTLSVerify,
		}
		return ldap.DialTLS("tcp", address, tlsConfig)
	}

	return ldap.Dial("tcp", address)
}

// searchUser 搜索用户
func (l *LDAPAuthenticator) searchUser(conn *ldap.Conn, username string) (string, *LDAPUserInfo, error) {
	// 构建搜索过滤器
	filter := fmt.Sprintf(l.config.UserFilter, ldap.EscapeFilter(username))

	// 搜索请求
	searchRequest := ldap.NewSearchRequest(
		l.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"dn", "cn", "mail", "displayName", "memberOf"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", nil, err
	}

	if len(result.Entries) == 0 {
		return "", nil, fmt.Errorf("user not found")
	}

	if len(result.Entries) > 1 {
		return "", nil, fmt.Errorf("multiple users found")
	}

	entry := result.Entries[0]
	userInfo := &LDAPUserInfo{
		Email:    entry.GetAttributeValue("mail"),
		FullName: entry.GetAttributeValue("displayName"),
	}

	// 如果 displayName 为空，使用 cn
	if userInfo.FullName == "" {
		userInfo.FullName = entry.GetAttributeValue("cn")
	}

	return entry.DN, userInfo, nil
}

// isUserInGroup 检查用户是否在指定组中
func (l *LDAPAuthenticator) isUserInGroup(conn *ldap.Conn, userDN, groupDN string) (bool, error) {
	// 重新绑定管理员账号（因为之前用用户账号绑定了）
	if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
		return false, err
	}

	// 搜索用户的 memberOf 属性
	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"memberOf"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return false, err
	}

	if len(result.Entries) == 0 {
		return false, nil
	}

	// 检查 memberOf 属性
	memberOfList := result.Entries[0].GetAttributeValues("memberOf")
	for _, memberOf := range memberOfList {
		if memberOf == groupDN {
			return true, nil
		}
	}

	return false, nil
}

// LDAPUser LDAP 用户信息
type LDAPUser struct {
	DN       string
	Username string
	Email    string
	FullName string
	IsAdmin  bool
}

// LDAPUserInfo LDAP 用户详细信息
type LDAPUserInfo struct {
	Email    string
	FullName string
}

