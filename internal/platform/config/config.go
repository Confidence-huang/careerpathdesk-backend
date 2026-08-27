/*
运行配置边界：把进程外部字符串转换为启动前可验证的 v2 数据库与 HTTP 事实。
LoadDatabase 供显式 migration 使用；Load 在其上增加 API 监听和浏览器同源边界。
调用示例：configuration, loadError := config.Load(os.Getenv)。
*/
package config

import (
	"errors"  // 暴露可稳定比较的配置错误分类。
	"net"     // 解析监听 host:port 并核对字面回环 IP。
	"net/url" // 解析数据库连接串，避免用模糊字符串包含判断保护数据边界。
	"strconv" // 将人工声明的 schema 版本解析成严格整数。
	"strings" // 清理环境变量的非业务空白，避免空格伪装成有效值。
)

var ErrMissingRuntimeMode = errors.New("runtime mode is required")                                     // 标识运行模式没有得到人工选择。
var ErrUnsupportedRuntimeMode = errors.New("runtime mode is unsupported")                              // 标识运行模式不属于已审查的数据边界。
var ErrMissingHTTPAddr = errors.New("HTTP address is required")                                        // 标识内部监听边界没有得到人工选择。
var ErrMissingPublicOrigin = errors.New("public origin is required")                                   // 标识浏览器同源边界没有得到人工选择。
var ErrMissingAccessTokenPrivateKeyFile = errors.New("access token private key file is required")      // 标识 JWT 签名密钥没有受保护来源。
var ErrDatabasePasswordInURL = errors.New("database password must use a protected file")               // 标识连接串会向进程参数暴露密码。
var ErrMissingDatabasePasswordFile = errors.New("database password file is required")                  // 标识数据库秘密没有受保护来源。
var ErrUnsafeSyntheticDatabase = errors.New("synthetic database name is required")                     // 标识合成进程可能连接到未隔离数据库。
var ErrUnsafeProductionDatabase = errors.New("production database name is required")                   // 标识生产进程可能连接到非生产或共享数据库。
var ErrInvalidMFAPolicy = errors.New("MFA policy must be explicitly true or false")                    // 标识生产未明确选择登录第二因素策略。
var ErrMissingMFAEncryptionKeyFile = errors.New("MFA encryption key file is required")                 // 标识生产 MFA 秘密没有独立密钥来源。
var ErrMissingPrivacyNoticeFile = errors.New("production privacy notice file is required")             // 标识生产运行没有受保护的审批摘要来源。
var ErrSyntheticPrivacyNoticeFile = errors.New("synthetic privacy notice file is forbidden")           // 标识合成运行试图读取生产审批摘要。
var ErrUnsafeProductionOrigin = errors.New("production public origin must use HTTPS")                  // 标识生产浏览器来源不是安全完整 origin。
var ErrUnsafeProductionHTTPAddr = errors.New("production HTTP address must use loopback")              // 标识生产 API 可能直接暴露公网。
var ErrSchemaVersionMismatch = errors.New("expected schema version does not match this binary")        // 标识部署声明与当前代码不属于同一 schema 合同。
var ErrSyntheticSeedOnly = errors.New("seed command is synthetic-only")                                // 标识 seed 被提交到正式或候选运行环境。
var ErrUnsafeSeedProfile = errors.New("synthetic seed profile is not approved")                        // 标识 seed 档案不是已审查的固定 Foundation 数据。
var ErrMissingSyntheticAccountPasswordFile = errors.New("synthetic account password file is required") // 标识合成账号密码没有受保护来源。

const SupportedSchemaVersion int64 = 9                       // 当前二进制要求学生协作、完整资料和跟进正文已迁移。
const SyntheticFoundationProfile = "synthetic-foundation-v1" // 唯一获准写入本地合成库的 seed 档案。

// Database 保存已经通过数据边界检查的 PostgreSQL 连接事实。
type Database struct {
	RuntimeMode           string // RuntimeMode 区分合成开发与未来正式候选环境。
	URL                   string // URL 不含密码，并明确 PostgreSQL 主机、端口和数据库名。
	PasswordFile          string // PasswordFile 指向权限受限且未纳入 Git 的秘密文件。
	ExpectedSchemaVersion int64  // ExpectedSchemaVersion 让 readiness 能核对数据库账本而不隐式迁移。
}

// Config 在数据库事实之上增加 API 进程的 HTTP 边界。
type Config struct {
	Database                         // 嵌入已验证数据库事实，避免 migration 重复 HTTP 配置。
	HTTPAddr                  string // HTTPAddr 是 Go 进程唯一允许监听的内部地址。
	PublicOrigin              string // PublicOrigin 是浏览器状态改变请求必须匹配的同源地址。
	AccessTokenPrivateKeyFile string // AccessTokenPrivateKeyFile 指向 0600 Ed25519 PKCS#8 PEM 文件。
	RequireMFA                bool   // RequireMFA 控制正常会话前是否必须完成第二因素。
	MFAEncryptionKeyFile      string // MFAEncryptionKeyFile 指向保护 TOTP secret 的独立 AES 密钥文件。
	PrivacyNoticeFile         string // PrivacyNoticeFile 只在 production 指向受保护的审批摘要；synthetic 必须为空。
}

// SyntheticSeed 保存已经证明只属于本地合成环境的 seed 配置。
type SyntheticSeed struct {
	Database                   // 复用相同的数据库、密码文件和 schema 版本边界。
	Profile             string // Profile 固定本轮可执行的合成数据集合身份。
	AccountPasswordFile string // AccountPasswordFile 指向 Git 外的合成账号初始密码文件。
}

// --- 读取并验证 API 启动配置 ---
func Load(getEnvironmentValue func(string) string) (Config, error) {
	database, databaseError := LoadDatabase(getEnvironmentValue) // 先证明数据环境和秘密来源。
	if databaseError != nil {                                    // 数据边界未知时不进入 HTTP 配置。
		return Config{}, databaseError
	}

	httpAddress := strings.TrimSpace(getEnvironmentValue("CAREERPATH_HTTP_ADDR")) // 读取显式内部监听地址，不允许 net/http 默认值。
	if httpAddress == "" {                                                        // 缺失地址时在创建监听器前停止。
		return Config{}, ErrMissingHTTPAddr
	}
	if database.RuntimeMode == "production" && !isLoopbackAddress(httpAddress) { // 生产 API 必须只接受同机边缘代理流量。
		return Config{}, ErrUnsafeProductionHTTPAddr
	}
	publicOrigin := strings.TrimSpace(getEnvironmentValue("CAREERPATH_PUBLIC_ORIGIN")) // 读取状态改变请求必须匹配的浏览器来源。
	if publicOrigin == "" {                                                            // 缺失来源时不允许进入 HTTP 运行阶段。
		return Config{}, ErrMissingPublicOrigin
	}
	if database.RuntimeMode == "production" && !isHTTPSOrigin(publicOrigin) { // 生产 Cookie 与状态改变请求只能绑定完整 HTTPS origin。
		return Config{}, ErrUnsafeProductionOrigin
	}
	accessTokenPrivateKeyFile := strings.TrimSpace(getEnvironmentValue("CAREERPATH_ACCESS_TOKEN_PRIVATE_KEY_FILE")) // 读取 JWT 私钥的受保护文件路径。
	if accessTokenPrivateKeyFile == "" {                                                                            // 禁止临时生成或使用源码内固定密钥。
		return Config{}, ErrMissingAccessTokenPrivateKeyFile
	}
	mfaPolicy := strings.ToLower(strings.TrimSpace(getEnvironmentValue("CAREERPATH_REQUIRE_MFA"))) // 生产必须用字面 true/false 明确选择第二因素策略。
	if database.RuntimeMode == "production" && mfaPolicy != "true" && mfaPolicy != "false" {
		return Config{}, ErrInvalidMFAPolicy
	}
	requireMFA := mfaPolicy == "true"                                                                    // 合成环境省略时维持无 MFA；生产已经由上方枚举验证。
	mfaEncryptionKeyFile := strings.TrimSpace(getEnvironmentValue("CAREERPATH_MFA_ENCRYPTION_KEY_FILE")) // 读取生产 MFA 数据的独立密钥路径。
	if database.RuntimeMode == "production" && requireMFA && mfaEncryptionKeyFile == "" {                // 只有启用 TOTP 时才要求其独立保护密钥。
		return Config{}, ErrMissingMFAEncryptionKeyFile
	}
	privacyNoticeFile := strings.TrimSpace(getEnvironmentValue("CAREERPATH_PRIVACY_NOTICE_FILE")) // 读取生产审批摘要路径，但不在配置层打开文件。
	if database.RuntimeMode == "production" && privacyNoticeFile == "" {                          // production 必须在连接数据库前声明审批来源。
		return Config{}, ErrMissingPrivacyNoticeFile
	}
	if database.RuntimeMode == "synthetic" && privacyNoticeFile != "" { // 合成环境只使用内存 DRAFT，禁止误接生产审批文件。
		return Config{}, ErrSyntheticPrivacyNoticeFile
	}

	return Config{
		Database: database, HTTPAddr: httpAddress, PublicOrigin: publicOrigin,
		AccessTokenPrivateKeyFile: accessTokenPrivateKeyFile, RequireMFA: requireMFA,
		MFAEncryptionKeyFile: mfaEncryptionKeyFile, PrivacyNoticeFile: privacyNoticeFile,
	}, nil // 反馈已经验证的完整 API 配置。
}

// isLoopbackAddress 用结构化网络解析拒绝通配、主机名、外部 IP 和缺失端口。
func isLoopbackAddress(value string) bool {
	host, port, splitError := net.SplitHostPort(value)
	if splitError != nil || port == "" {
		return false
	}
	parsedHost := net.ParseIP(host)
	return parsedHost != nil && parsedHost.IsLoopback()
}

// isHTTPSOrigin 只接受无凭据、查询、片段或业务路径的完整 HTTPS origin。
func isHTTPSOrigin(value string) bool {
	parsedOrigin, parseError := url.Parse(value)
	if parseError != nil || parsedOrigin.Scheme != "https" || parsedOrigin.Hostname() == "" || parsedOrigin.User != nil {
		return false
	}
	return (parsedOrigin.Path == "" || parsedOrigin.Path == "/") && parsedOrigin.RawQuery == "" && parsedOrigin.Fragment == ""
}

// --- 读取并验证 PostgreSQL 配置 ---
func LoadDatabase(getEnvironmentValue func(string) string) (Database, error) {
	runtimeMode := strings.TrimSpace(getEnvironmentValue("CAREERPATH_RUNTIME_MODE")) // 从唯一注入入口读取运行边界。
	if runtimeMode == "" {                                                           // 未选择环境时拒绝继续，避免错误数据源回退。
		return Database{}, ErrMissingRuntimeMode
	}
	if runtimeMode != "synthetic" && runtimeMode != "production" { // 未审查的环境不得继承任一数据库规则。
		return Database{}, ErrUnsupportedRuntimeMode
	}

	databaseURL := strings.TrimSpace(getEnvironmentValue("CAREERPATH_DATABASE_URL")) // 读取显式数据库地址，不提供默认路径。
	parsedDatabaseURL, parseDatabaseURLError := url.Parse(databaseURL)               // 结构化解析失败必须在接触 pgx 前关闭。
	if parseDatabaseURLError != nil || parsedDatabaseURL == nil {
		if runtimeMode == "production" {
			return Database{}, ErrUnsafeProductionDatabase
		}
		return Database{}, ErrUnsafeSyntheticDatabase
	}
	databaseName := strings.TrimPrefix(parsedDatabaseURL.Path, "/") // PostgreSQL URL 的路径部分代表目标数据库名。
	queryValues := parsedDatabaseURL.Query()                        // pgx 会让 query 中的 database/dbname 覆盖路径，必须先拒绝双重身份。
	if queryValues.Has("database") || queryValues.Has("dbname") {   // 唯一数据库身份只能来自 URI path，禁止解析器优先级改变实际目标。
		if runtimeMode == "production" {
			return Database{}, ErrUnsafeProductionDatabase
		}
		return Database{}, ErrUnsafeSyntheticDatabase
	}
	if runtimeMode == "synthetic" && databaseName != "careerpathdesk_synthetic" { // 合成进程只能进入唯一命名的数据边界。
		return Database{}, ErrUnsafeSyntheticDatabase
	}
	if runtimeMode == "production" && databaseName != "careerpathdesk_production" { // 生产进程只能进入独立生产数据库。
		return Database{}, ErrUnsafeProductionDatabase
	}
	if _, hasPassword := parsedDatabaseURL.User.Password(); hasPassword { // 连接 URL 会进入进程和诊断边界，禁止携带密码。
		return Database{}, ErrDatabasePasswordInURL
	}

	passwordFile := strings.TrimSpace(getEnvironmentValue("CAREERPATH_DATABASE_PASSWORD_FILE")) // 读取数据库秘密的受保护文件路径。
	if passwordFile == "" {                                                                     // 未提供秘密来源时不允许空密码或隐式宿主回退。
		return Database{}, ErrMissingDatabasePasswordFile
	}
	expectedSchemaVersion, parseVersionError := strconv.ParseInt(strings.TrimSpace(getEnvironmentValue("CAREERPATH_EXPECTED_SCHEMA_VERSION")), 10, 64) // 解析部署者明确声明的 schema 合同。
	if parseVersionError != nil || expectedSchemaVersion != SupportedSchemaVersion {                                                                   // 缺失、非整数或不同版本都不允许当前二进制启动。
		return Database{}, ErrSchemaVersionMismatch
	}

	return Database{RuntimeMode: runtimeMode, URL: databaseURL, PasswordFile: passwordFile, ExpectedSchemaVersion: expectedSchemaVersion}, nil // 反馈可供 migration 或 API 使用的数据事实。
}

// --- 读取只允许合成环境使用的 seed 配置 ---
func LoadSyntheticSeed(getEnvironmentValue func(string) string) (SyntheticSeed, error) {
	database, loadError := LoadDatabase(getEnvironmentValue) // 先验证连接、秘密来源与 schema 声明。
	if loadError != nil {                                    // 基础边界未知时不进入 seed 专属判断。
		return SyntheticSeed{}, loadError
	}
	if database.RuntimeMode != "synthetic" { // 正式或候选环境永远不能使用合成数据入口。
		return SyntheticSeed{}, ErrSyntheticSeedOnly
	}
	profile := strings.TrimSpace(getEnvironmentValue("CAREERPATH_SEED_PROFILE")) // 读取人工声明的 seed 档案身份。
	if profile != SyntheticFoundationProfile {                                   // 空值、导入档案或未来版本都需重新审查。
		return SyntheticSeed{}, ErrUnsafeSeedProfile
	}
	accountPasswordFile := strings.TrimSpace(getEnvironmentValue("CAREERPATH_SYNTHETIC_ACCOUNT_PASSWORD_FILE")) // 读取只供合成账号使用的受保护密码文件路径。
	if accountPasswordFile == "" {                                                                              // 禁止源码默认值或数据库密码复用成为账号凭据。
		return SyntheticSeed{}, ErrMissingSyntheticAccountPasswordFile
	}

	return SyntheticSeed{Database: database, Profile: profile, AccountPasswordFile: accountPasswordFile}, nil // 反馈已证明只指向合成数据库、固定档案和受保护账号秘密的配置。
}
