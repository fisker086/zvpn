package auth

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig LDAP 配置
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

	// LDAP属性映射配置
	AttributeMapping AttributeMapping
}

// AttributeMapping LDAP属性映射配置
type AttributeMapping struct {
	UsernameAttribute string // 用户名属性，例如: "uid", "sAMAccountName", "cn"
	EmailAttribute    string // 邮箱属性，例如: "mail", "email"
	FullNameAttribute string // 全名属性，例如: "displayName", "cn", "name"
	MemberOfAttribute string // 组成员属性，例如: "memberOf", "groupMembership"
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

	// 验证必填配置
	if l.config.Host == "" || l.config.BindDN == "" || l.config.BaseDN == "" || l.config.UserFilter == "" {
		return nil, fmt.Errorf("LDAP configuration is incomplete: Host, BindDN, BaseDN, and UserFilter are required")
	}

	// 验证 UserFilter 格式
	if !strings.Contains(l.config.UserFilter, "%s") && !strings.Contains(l.config.UserFilter, "{0}") {
		return nil, fmt.Errorf("UserFilter must contain %%s or {0} placeholder, got: %s", l.config.UserFilter)
	}

	// 验证用户名和密码
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// 连接 LDAP 服务器（短连接，每次认证都创建新连接）
	conn, err := l.connect()
	if err != nil {
		log.Printf("LDAP: Connection failed for user '%s' to %s:%d: %v", username, l.config.Host, l.config.Port, err)
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	// 确保连接立即关闭（短连接模式）
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("LDAP: Warning - Error closing connection for user '%s': %v", username, err)
		}
	}()

	// 使用管理员账号绑定
	if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
		log.Printf("LDAP: Admin bind failed for user '%s': %v", username, err)
		return nil, fmt.Errorf("failed to bind with admin account: %w", err)
	}

	// 搜索用户
	userDN, userInfo, err := l.searchUser(conn, username)
	if err != nil {
		log.Printf("LDAP: User search failed for username '%s' with filter '%s' in BaseDN '%s': %v",
			username, l.config.UserFilter, l.config.BaseDN, err)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	log.Printf("LDAP: Found user '%s' with DN: %s", username, userDN)

	// 使用用户凭据验证
	if err := conn.Bind(userDN, password); err != nil {
		log.Printf("LDAP: Authentication failed for user '%s' (DN: %s): %v", username, userDN, err)
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	// 检查用户是否是管理员
	isAdmin := false
	if l.config.AdminGroup != "" {
		isAdmin, err = l.isUserInGroup(conn, userDN, l.config.AdminGroup)
		if err != nil {
			// 管理员组检查失败不影响登录，只记录日志
			log.Printf("Warning: Failed to check admin group: %v", err)
		}
	}

	// 获取属性映射配置
	_, emailAttr, fullNameAttr, memberOfAttr := l.getAttributeMapping()

	// 重新搜索用户以获取完整属性（用于同步和存储）
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
		// 收集所有LDAP属性（用于存储到数据库，便于扩展）
		// 规范化属性：单值属性存储为字符串，多值属性存储为数组
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

// connect 连接到 LDAP 服务器（短连接，每次认证都创建新连接）
func (l *LDAPAuthenticator) connect() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", l.config.Host, l.config.Port)

	var conn *ldap.Conn
	var err error

	// 使用短连接，不重试（短连接失败通常意味着真的有问题，重试可能导致端口耗尽）
	if l.config.UseSSL {
		// LDAPS (直接 TLS 连接，端口 636)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: l.config.SkipTLSVerify,
			ServerName:         l.config.Host, // 设置 SNI，某些服务器需要
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to LDAPS server %s: %w", address, err)
		}
	} else {
		// 普通 LDAP 连接（端口 389）
		conn, err = ldap.Dial("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", address, err)
		}
	}

	// 设置连接超时（10秒足够短连接使用）
	conn.SetTimeout(10 * time.Second)

	return conn, nil
}

// searchUser 搜索用户
func (l *LDAPAuthenticator) searchUser(conn *ldap.Conn, username string) (string, *LDAPUserInfo, error) {
	// 构建搜索过滤器
	// 支持两种格式：%s (Go fmt) 和 {0} (常见 LDAP 格式)
	escapedUsername := ldap.EscapeFilter(username)
	filter := l.config.UserFilter

	// 如果包含 {0}，替换为转义后的用户名
	if strings.Contains(filter, "{0}") {
		filter = strings.ReplaceAll(filter, "{0}", escapedUsername)
	} else if strings.Contains(filter, "%s") {
		// 如果包含 %s，使用 fmt.Sprintf
		filter = fmt.Sprintf(filter, escapedUsername)
	} else {
		// 如果都不包含，说明 UserFilter 格式错误（应该在 Authenticate 函数中已经检查过）
		return "", nil, fmt.Errorf("user_filter format error: must contain %%s or {0} placeholder, got: %s", filter)
	}

	// 获取属性映射配置
	_, emailAttr, fullNameAttr, memberOfAttr := l.getAttributeMapping()

	// 搜索请求（查询所有需要的属性）
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

	// 使用配置的属性映射获取属性值（变量已在上面定义）
	email := entry.GetAttributeValue(emailAttr)
	fullName := entry.GetAttributeValue(fullNameAttr)
	// 如果全名为空，尝试使用cn作为fallback
	if fullName == "" {
		fullName = entry.GetAttributeValue("cn")
	}

	userInfo := &LDAPUserInfo{
		Email:    email,
		FullName: fullName,
	}

	return entry.DN, userInfo, nil
}

// isUserInGroup 检查用户是否在指定组中
func (l *LDAPAuthenticator) isUserInGroup(conn *ldap.Conn, userDN, groupDN string) (bool, error) {
	// 重新绑定管理员账号（因为之前用用户账号绑定了）
	if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
		return false, err
	}

	// 获取属性映射配置
	_, _, _, memberOfAttr := l.getAttributeMapping()

	// 搜索用户的组成员属性
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

	// 检查组成员属性
	memberOfList := result.Entries[0].GetAttributeValues(memberOfAttr)
	for _, memberOf := range memberOfList {
		if memberOf == groupDN {
			return true, nil
		}
	}

	return false, nil
}

// inferUsernameAttributeFromFilter 从UserFilter推断用户名属性
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
	// 默认返回空，让调用方使用fallback逻辑
	return ""
}

// getAttributeMapping 获取属性映射配置（带默认值）
func (l *LDAPAuthenticator) getAttributeMapping() (usernameAttr, emailAttr, fullNameAttr, memberOfAttr string) {
	// 用户名属性（从配置或从UserFilter推断）
	usernameAttr = l.config.AttributeMapping.UsernameAttribute
	if usernameAttr == "" {
		usernameAttr = l.inferUsernameAttributeFromFilter()
	}

	// 其他属性映射（带默认值）
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

// extractUsernameFromEntry 从LDAP entry中提取用户名（支持多种fallback策略）
func (l *LDAPAuthenticator) extractUsernameFromEntry(entry *ldap.Entry, usernameAttr string) string {
	// 优先使用配置的属性
	if usernameAttr != "" {
		if username := entry.GetAttributeValue(usernameAttr); username != "" {
			return username
		}
	}

	// 如果配置的属性没有值，尝试从UserFilter推断
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

	// 如果还是没有，尝试从常见属性获取（按优先级）
	commonAttrs := []string{"uid", "sAMAccountName", "cn"}
	for _, attr := range commonAttrs {
		if username := entry.GetAttributeValue(attr); username != "" {
			return username
		}
	}

	// 如果还是没有，从 DN 中提取（例如：cn=username,ou=users,dc=example,dc=com）
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

// normalizeLDAPAttributes 规范化LDAP属性
// 单值属性（如cn、mail）存储为字符串，多值属性（如memberOf）存储为数组
// 返回格式：map[string]interface{}，其中值可以是string或[]string
func normalizeLDAPAttributes(attrs []*ldap.EntryAttribute) map[string]interface{} {
	result := make(map[string]interface{})

	for _, attr := range attrs {
		// 如果属性只有一个值，存储为字符串（节省空间，更符合直觉）
		if len(attr.Values) == 1 {
			result[attr.Name] = attr.Values[0]
		} else if len(attr.Values) > 1 {
			// 多个值，存储为数组
			result[attr.Name] = attr.Values
		}
		// 如果 len(attr.Values) == 0，跳过（空值不存储）
	}

	return result
}

// LDAPUser LDAP 用户信息
type LDAPUser struct {
	DN         string                 // Distinguished Name
	Username   string                 // 用户名 (uid/sAMAccountName/cn)
	Email      string                 // 邮箱 (mail)
	FullName   string                 // 全名/中文名 (displayName/cn)
	IsAdmin    bool                   // 是否是管理员
	Attributes map[string]interface{} // LDAP原始属性（单值属性为字符串，多值属性为数组）
}

// LDAPUserInfo LDAP 用户详细信息
type LDAPUserInfo struct {
	Email    string
	FullName string
}

// SearchAllUsers 搜索 LDAP 中的所有用户（用于同步）
// 返回所有匹配 UserFilter 的用户列表
func (l *LDAPAuthenticator) SearchAllUsers() ([]*LDAPUser, error) {
	if !l.config.Enabled {
		return nil, fmt.Errorf("LDAP is not enabled")
	}

	// 验证必填配置
	if l.config.Host == "" || l.config.BindDN == "" || l.config.BaseDN == "" || l.config.UserFilter == "" {
		return nil, fmt.Errorf("LDAP configuration is incomplete: Host, BindDN, BaseDN, and UserFilter are required")
	}

	// 连接 LDAP 服务器（短连接）
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

	// 使用管理员账号绑定
	if err := conn.Bind(l.config.BindDN, l.config.BindPassword); err != nil {
		log.Printf("LDAP: Admin bind failed for SearchAllUsers: %v", err)
		return nil, fmt.Errorf("failed to bind with admin account: %w", err)
	}

	// 构建搜索所有用户的过滤器
	// 从 UserFilter 中提取基础过滤器（去掉 %s 或 {0}）
	baseFilter := l.config.UserFilter
	// 替换占位符为通配符，搜索所有用户
	// 例如: (uid=%s) -> (uid=*), (sAMAccountName={0}) -> (sAMAccountName=*)
	if strings.Contains(baseFilter, "{0}") {
		baseFilter = strings.ReplaceAll(baseFilter, "{0}", "*")
	} else if strings.Contains(baseFilter, "%s") {
		// 使用 * 替换 %s（通配符）
		baseFilter = strings.ReplaceAll(baseFilter, "%s", "*")
	} else {
		// 如果 UserFilter 没有占位符，直接使用
		// 但这种情况不太可能，因为 UserFilter 应该包含占位符
	}

	// 获取属性映射配置
	usernameAttr, emailAttr, fullNameAttr, memberOfAttr := l.getAttributeMapping()

	// 构建属性列表（包含配置的属性以及常见的fallback属性）
	attributes := []string{"dn", "cn", emailAttr, fullNameAttr, memberOfAttr}
	if usernameAttr != "" {
		attributes = append(attributes, usernameAttr)
	}
	// 添加常见的fallback属性
	attributes = append(attributes, "uid", "sAMAccountName")

	// 搜索请求
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
		// 提取用户名（使用优化的提取函数）
		username := l.extractUsernameFromEntry(entry, usernameAttr)
		if username == "" {
			// 跳过无法提取用户名的条目
			continue
		}

		// 检查用户是否是管理员
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

		// 提取LDAP属性（使用配置的属性映射）
		email := entry.GetAttributeValue(emailAttr)
		fullName := entry.GetAttributeValue(fullNameAttr)
		// 如果全名为空，尝试使用cn作为fallback
		if fullName == "" {
			fullName = entry.GetAttributeValue("cn")
		}

		// 收集所有LDAP属性（用于存储到数据库，便于扩展）
		// 规范化属性：单值属性存储为字符串，多值属性存储为数组
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
