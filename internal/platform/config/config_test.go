/*
运行配置行为测试：验证 API 在接触数据库或监听端口前拒绝不明确的环境。
测试通过公开 Load 入口传入合成环境变量，不读取宿主机秘密。
调用示例：go test ./internal/platform/config -count=1。
*/
package config

import (
	"errors"  // 比较公开错误分类，不依赖错误文字。
	"testing" // 运行 Go 标准行为测试。
)

// --- 当前二进制只接受包含学生协作关系的精确 schema 9 ---
func TestSupportedSchemaVersionIsNine(t *testing.T) {
	if SupportedSchemaVersion != 9 {
		t.Fatalf("expected supported schema version 9, got %d", SupportedSchemaVersion)
	}
}

// --- 缺失运行模式时失败关闭 ---
func TestLoadRejectsMissingRuntimeMode(t *testing.T) {
	_, loadError := Load(func(string) string { return "" }) // 模拟完全缺失的部署配置。
	if !errors.Is(loadError, ErrMissingRuntimeMode) {       // 只有稳定错误分类能驱动启动失败反馈。
		t.Fatalf("expected ErrMissingRuntimeMode, got %v", loadError)
	}
}

// --- 运行模式只接受已审查的 synthetic 与 production ---
func TestLoadRejectsUnknownRuntimeMode(t *testing.T) {
	environment := map[string]string{ // 其余数据库配置完整，确保失败只来自未知运行身份。
		"CAREERPATH_RUNTIME_MODE":            "staging",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:5432/careerpathdesk_staging?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/protected/postgres_password",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}

	_, loadError := LoadDatabase(func(key string) string { return environment[key] })
	if !errors.Is(loadError, ErrUnsupportedRuntimeMode) {
		t.Fatalf("expected ErrUnsupportedRuntimeMode, got %v", loadError)
	}
}

// --- 生产运行身份只能连接唯一命名的生产数据库 ---
func TestLoadProductionDatabaseBoundary(t *testing.T) {
	base := map[string]string{
		"CAREERPATH_RUNTIME_MODE":            "production",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/protected/postgres_password",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}

	for testName, databaseURL := range map[string]string{
		"synthetic":         "postgres://careerpathdesk_production@127.0.0.1:5432/careerpathdesk_synthetic?sslmode=disable",
		"empty":             "postgres://careerpathdesk_production@127.0.0.1:5432",
		"other":             "postgres://careerpathdesk_production@127.0.0.1:5432/careerpathdesk_customer?sslmode=disable",
		"malformed":         "postgres://careerpathdesk_production@127.0.0.1:5432/careerpathdesk_%zz",
		"dbname_override":   "postgres://careerpathdesk_production@127.0.0.1:5432/careerpathdesk_production?dbname=careerpathdesk_synthetic",
		"database_override": "postgres://careerpathdesk_production@127.0.0.1:5432/careerpathdesk_production?database=careerpathdesk_synthetic",
	} {
		t.Run(testName, func(t *testing.T) {
			environment := mapsClone(base)
			environment["CAREERPATH_DATABASE_URL"] = databaseURL
			_, loadError := LoadDatabase(func(key string) string { return environment[key] })
			if !errors.Is(loadError, ErrUnsafeProductionDatabase) {
				t.Fatalf("expected ErrUnsafeProductionDatabase, got %v", loadError)
			}
		})
	}

	environment := mapsClone(base)
	environment["CAREERPATH_DATABASE_URL"] = "postgres://careerpathdesk_production@127.0.0.1:5432/careerpathdesk_production?sslmode=disable"
	configuration, loadError := LoadDatabase(func(key string) string { return environment[key] })
	if loadError != nil {
		t.Fatalf("expected production database configuration to load, got %v", loadError)
	}
	if configuration.RuntimeMode != "production" {
		t.Fatalf("unexpected runtime mode: %s", configuration.RuntimeMode)
	}
}

// --- 生产登录流程必须显式选择 MFA 策略，关闭时不得继续依赖无用密钥 ---
func TestLoadProductionAcceptsExplicitlyDisabledMFA(t *testing.T) {
	base := productionEnvironment()
	base["CAREERPATH_REQUIRE_MFA"] = "false"
	delete(base, "CAREERPATH_MFA_ENCRYPTION_KEY_FILE")

	configuration, loadError := Load(func(key string) string { return base[key] })
	if loadError != nil {
		t.Fatalf("expected explicitly MFA-disabled production configuration to load, got %v", loadError)
	}
	if configuration.RequireMFA || configuration.MFAEncryptionKeyFile != "" {
		t.Fatal("expected production MFA and its unused key dependency to remain disabled")
	}
}

// --- 生产不得把缺失或拼错的开关悄悄解释为关闭 MFA ---
func TestLoadProductionRequiresExplicitMFAPolicy(t *testing.T) {
	for _, policy := range []string{"", "disabled", "yes"} {
		t.Run("policy_"+policy, func(t *testing.T) {
			environment := productionEnvironment()
			environment["CAREERPATH_REQUIRE_MFA"] = policy

			_, loadError := Load(func(key string) string { return environment[key] })
			if !errors.Is(loadError, ErrInvalidMFAPolicy) {
				t.Fatalf("expected ErrInvalidMFAPolicy, got %v", loadError)
			}
		})
	}
}

// --- 生产 MFA 密钥必须来自显式受保护文件 ---
func TestLoadProductionRequiresMFAEncryptionKeyFile(t *testing.T) {
	environment := productionEnvironment()
	delete(environment, "CAREERPATH_MFA_ENCRYPTION_KEY_FILE")

	_, loadError := Load(func(key string) string { return environment[key] })
	if !errors.Is(loadError, ErrMissingMFAEncryptionKeyFile) {
		t.Fatalf("expected ErrMissingMFAEncryptionKeyFile, got %v", loadError)
	}

	environment["CAREERPATH_MFA_ENCRYPTION_KEY_FILE"] = "/protected/mfa_encryption_key"
	configuration, loadError := Load(func(key string) string { return environment[key] })
	if loadError != nil {
		t.Fatalf("expected protected MFA key file to load, got %v", loadError)
	}
	if configuration.MFAEncryptionKeyFile != "/protected/mfa_encryption_key" {
		t.Fatal("unexpected MFA encryption key file")
	}
}

// --- 隐私审批文件只属于 production 且 production 不得缺失 ---
func TestLoadBindsPrivacyNoticeFileToProductionRuntime(t *testing.T) {
	production := productionEnvironment()                // 先从完整 production 事实移除唯一审批文件变量。
	delete(production, "CAREERPATH_PRIVACY_NOTICE_FILE") // 缺失审批摘要必须在应用读取文件前失败关闭。
	_, missingError := Load(func(key string) string { return production[key] })
	if !errors.Is(missingError, ErrMissingPrivacyNoticeFile) {
		t.Fatalf("expected ErrMissingPrivacyNoticeFile, got %v", missingError)
	}

	synthetic := syntheticEnvironment()                                            // 合成运行只允许进程内 DRAFT，不读取生产审批输入。
	synthetic["CAREERPATH_PRIVACY_NOTICE_FILE"] = "/protected/privacy-notice.json" // 即使路径看似受保护也不得跨环境复用。
	_, syntheticError := Load(func(key string) string { return synthetic[key] })
	if !errors.Is(syntheticError, ErrSyntheticPrivacyNoticeFile) {
		t.Fatalf("expected ErrSyntheticPrivacyNoticeFile, got %v", syntheticError)
	}

	approvedProduction := productionEnvironment() // 完整 production 环境应保留路径供应用层安全打开。
	configuration, loadError := Load(func(key string) string { return approvedProduction[key] })
	if loadError != nil || configuration.PrivacyNoticeFile != "/protected/privacy-notice.json" {
		t.Fatalf("expected production privacy notice path, got %#v %v", configuration, loadError)
	}
}

// --- 生产浏览器来源必须是完整 HTTPS origin ---
func TestLoadProductionRejectsUnsafePublicOrigin(t *testing.T) {
	for testName, origin := range map[string]string{
		"plain_http": "http://careerpathdesk.example",
		"relative":   "careerpathdesk.example",
		"with_path":  "https://careerpathdesk.example/admin",
	} {
		t.Run(testName, func(t *testing.T) {
			environment := productionEnvironment()
			environment["CAREERPATH_PUBLIC_ORIGIN"] = origin
			_, loadError := Load(func(key string) string { return environment[key] })
			if !errors.Is(loadError, ErrUnsafeProductionOrigin) {
				t.Fatalf("expected ErrUnsafeProductionOrigin, got %v", loadError)
			}
		})
	}
}

// --- 生产 API 只接受带端口的字面回环地址 ---
func TestLoadProductionRejectsUnsafeHTTPAddress(t *testing.T) {
	for testName, address := range map[string]string{
		"wildcard":     "0.0.0.0:8280",
		"external":     "192.0.2.10:8280",
		"hostname":     "localhost:8280",
		"missing_port": "127.0.0.1",
	} {
		t.Run(testName, func(t *testing.T) {
			environment := productionEnvironment()
			environment["CAREERPATH_HTTP_ADDR"] = address
			_, loadError := Load(func(key string) string { return environment[key] })
			if !errors.Is(loadError, ErrUnsafeProductionHTTPAddr) {
				t.Fatalf("expected ErrUnsafeProductionHTTPAddr, got %v", loadError)
			}
		})
	}

	environment := productionEnvironment()
	environment["CAREERPATH_HTTP_ADDR"] = "[::1]:8280"
	if _, loadError := Load(func(key string) string { return environment[key] }); loadError != nil {
		t.Fatalf("expected IPv6 loopback address to load, got %v", loadError)
	}
}

func productionEnvironment() map[string]string {
	return map[string]string{
		"CAREERPATH_RUNTIME_MODE":                  "production",
		"CAREERPATH_HTTP_ADDR":                     "127.0.0.1:8280",
		"CAREERPATH_DATABASE_URL":                  "postgres://careerpathdesk_production@127.0.0.1:5432/careerpathdesk_production?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":        "/protected/postgres_password",
		"CAREERPATH_PUBLIC_ORIGIN":                 "https://careerpathdesk.example",
		"CAREERPATH_ACCESS_TOKEN_PRIVATE_KEY_FILE": "/protected/access_token_private_key.pem",
		"CAREERPATH_REQUIRE_MFA":                   "true",
		"CAREERPATH_MFA_ENCRYPTION_KEY_FILE":       "/protected/mfa_encryption_key",
		"CAREERPATH_PRIVACY_NOTICE_FILE":           "/protected/privacy-notice.json",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION":       "9",
	}
}

func mapsClone(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

// --- 合成模式拒绝未标记数据库 ---
func TestLoadRejectsSyntheticModeWithUnmarkedDatabase(t *testing.T) {
	environment := map[string]string{ // 构造看似完整但数据库边界危险的启动输入。
		"CAREERPATH_RUNTIME_MODE": "synthetic",                       // 明确要求只使用合成数据。
		"CAREERPATH_DATABASE_URL": "postgres://local/careerpathdesk", // 故意缺少 synthetic 标识。
	}

	_, loadError := Load(func(key string) string { return environment[key] }) // 从公开入口验证整套输入。
	if !errors.Is(loadError, ErrUnsafeSyntheticDatabase) {                    // 危险库名必须成为稳定启动失败。
		t.Fatalf("expected ErrUnsafeSyntheticDatabase, got %v", loadError)
	}
}

// --- 完整合成配置通过启动门禁 ---
func TestLoadAcceptsExplicitSyntheticConfiguration(t *testing.T) {
	environment := syntheticEnvironment() // 构造只指向回环和合成数据库的安全本地配置。

	configuration, loadError := Load(func(key string) string { return environment[key] }) // 通过唯一公开入口读取安全配置。
	if loadError != nil {                                                                 // 完整显式输入不应被拒绝。
		t.Fatalf("expected configuration to load, got %v", loadError)
	}
	if configuration.HTTPAddr != "127.0.0.1:8180" { // 内部监听必须保留明确回环地址。
		t.Fatalf("unexpected HTTP address: %s", configuration.HTTPAddr)
	}
	if configuration.PublicOrigin != "http://127.0.0.1:5173" { // 浏览器来源必须保持精确匹配值。
		t.Fatalf("unexpected public origin: %s", configuration.PublicOrigin)
	}
	if configuration.AccessTokenPrivateKeyFile != "/protected/access_token_private_key.pem" { // 私钥路径必须原样传给受保护文件加载器。
		t.Fatal("unexpected access token private key file")
	}
}

func syntheticEnvironment() map[string]string {
	return map[string]string{ // 复用不携带 production 审批文件的完整合成配置。
		"CAREERPATH_RUNTIME_MODE":                  "synthetic",
		"CAREERPATH_HTTP_ADDR":                     "127.0.0.1:8180",
		"CAREERPATH_DATABASE_URL":                  "postgres://careerpathdesk@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":        "/protected/postgres_password",
		"CAREERPATH_PUBLIC_ORIGIN":                 "http://127.0.0.1:5173",
		"CAREERPATH_ACCESS_TOKEN_PRIVATE_KEY_FILE": "/protected/access_token_private_key.pem",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION":       "9",
	}
}

// --- 缺失内部监听地址时失败关闭 ---
func TestLoadRejectsMissingHTTPAddress(t *testing.T) {
	environment := map[string]string{ // 提供安全数据库，但故意省略进程监听边界。
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/protected/postgres_password",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}

	_, loadError := Load(func(key string) string { return environment[key] }) // 从公开入口验证缺失地址。
	if !errors.Is(loadError, ErrMissingHTTPAddr) {                            // 禁止 net/http 回退到意外默认监听。
		t.Fatalf("expected ErrMissingHTTPAddr, got %v", loadError)
	}
}

// --- 缺失浏览器来源时失败关闭 ---
func TestLoadRejectsMissingPublicOrigin(t *testing.T) {
	environment := map[string]string{ // 提供进程和数据库边界，但故意省略浏览器同源事实。
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_HTTP_ADDR":               "127.0.0.1:8180",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/protected/postgres_password",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}

	_, loadError := Load(func(key string) string { return environment[key] }) // 从公开入口验证缺失来源。
	if !errors.Is(loadError, ErrMissingPublicOrigin) {                        // 未知来源不能被状态改变中间件猜测。
		t.Fatalf("expected ErrMissingPublicOrigin, got %v", loadError)
	}
}

// --- 缺失访问令牌私钥文件时失败关闭 ---
func TestLoadRejectsMissingAccessTokenPrivateKeyFile(t *testing.T) {
	environment := map[string]string{ // 提供数据库和 HTTP 边界，但故意省略 JWT 签名秘密来源。
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_HTTP_ADDR":               "127.0.0.1:8180",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/protected/postgres_password",
		"CAREERPATH_PUBLIC_ORIGIN":           "http://127.0.0.1:5173",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}

	_, loadError := Load(func(key string) string { return environment[key] }) // 从唯一 API 配置入口提交缺失密钥的环境。
	if !errors.Is(loadError, ErrMissingAccessTokenPrivateKeyFile) {           // 禁止运行时生成临时密钥导致重启后全部令牌失效。
		t.Fatalf("expected ErrMissingAccessTokenPrivateKeyFile, got %v", loadError)
	}
}

// --- 数据库密码不得出现在连接 URL ---
func TestLoadRejectsDatabasePasswordInURL(t *testing.T) {
	environment := map[string]string{ // 构造边界完整但会把密码暴露给进程参数的配置。
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_HTTP_ADDR":               "127.0.0.1:8180",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk:visible-secret@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_PUBLIC_ORIGIN":           "http://127.0.0.1:5173",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}

	_, loadError := Load(func(key string) string { return environment[key] }) // 从公开入口验证危险连接串。
	if !errors.Is(loadError, ErrDatabasePasswordInURL) {                      // 密码必须改由 0600 文件注入。
		t.Fatalf("expected ErrDatabasePasswordInURL, got %v", loadError)
	}
}

// --- 缺失数据库密码文件时失败关闭 ---
func TestLoadRejectsMissingDatabasePasswordFile(t *testing.T) {
	environment := map[string]string{ // 提供其余边界，但故意省略受保护密码来源。
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_HTTP_ADDR":               "127.0.0.1:8180",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_PUBLIC_ORIGIN":           "http://127.0.0.1:5173",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}

	_, loadError := Load(func(key string) string { return environment[key] }) // 从公开入口验证秘密来源缺失。
	if !errors.Is(loadError, ErrMissingDatabasePasswordFile) {                // 进程不得回退到空密码或 URL 密码。
		t.Fatalf("expected ErrMissingDatabasePasswordFile, got %v", loadError)
	}
}

// --- 运行声明与当前二进制 schema 版本不一致时失败关闭 ---
func TestLoadDatabaseRejectsSchemaVersionDrift(t *testing.T) {
	environment := map[string]string{ // 构造安全连接事实，但故意声明另一个 schema 版本。
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/protected/postgres_password",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "1",
	}

	_, loadError := LoadDatabase(func(key string) string { return environment[key] }) // 从 migration/API 共用配置入口验证版本声明。
	if !errors.Is(loadError, ErrSchemaVersionMismatch) {                              // 漂移必须成为稳定启动失败，而不是隐式修复。
		t.Fatalf("expected ErrSchemaVersionMismatch, got %v", loadError)
	}
}

// --- 合成 seed 入口拒绝任何非 synthetic 运行模式 ---
func TestLoadSyntheticSeedRejectsProductionRuntime(t *testing.T) {
	environment := map[string]string{ // 构造完整 production 连接，但故意提交给合成 seed 入口。
		"CAREERPATH_RUNTIME_MODE":            "production",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:5432/careerpathdesk_production?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/protected/postgres_password",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
		"CAREERPATH_SEED_PROFILE":            "synthetic-foundation-v1",
	}

	_, loadError := LoadSyntheticSeed(func(key string) string { return environment[key] }) // 从 seed 唯一配置入口验证运行边界。
	if !errors.Is(loadError, ErrSyntheticSeedOnly) {                                       // 正式环境必须在打开 seed 文件或数据库前被拒绝。
		t.Fatalf("expected ErrSyntheticSeedOnly, got %v", loadError)
	}
}

// --- 合成 seed 入口只接受已审查的 Foundation 数据档案 ---
func TestLoadSyntheticSeedRejectsUnknownProfile(t *testing.T) {
	environment := map[string]string{ // 构造完整合成连接，但故意指定未审查 seed 档案。
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/protected/postgres_password",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
		"CAREERPATH_SEED_PROFILE":            "customer-import",
	}

	_, loadError := LoadSyntheticSeed(func(key string) string { return environment[key] }) // 从唯一 seed 配置入口提交未知档案。
	if !errors.Is(loadError, ErrUnsafeSeedProfile) {                                       // 未知档案不得进入文件读取或数据库阶段。
		t.Fatalf("expected ErrUnsafeSeedProfile, got %v", loadError)
	}
}

// --- 合成 seed 入口拒绝源码默认密码或缺失的账号秘密来源 ---
func TestLoadSyntheticSeedRequiresAccountPasswordFile(t *testing.T) {
	environment := map[string]string{ // 构造完整合成连接和获准档案，但故意不提供账号密码文件。
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:55432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/protected/postgres_password",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
		"CAREERPATH_SEED_PROFILE":            "synthetic-foundation-v1",
	}

	_, loadError := LoadSyntheticSeed(func(key string) string { return environment[key] }) // 从唯一配置入口验证账号秘密来源门禁。
	if !errors.Is(loadError, ErrMissingSyntheticAccountPasswordFile) {                     // 缺失必须形成稳定失败，不能回退到源码密码。
		t.Fatalf("expected ErrMissingSyntheticAccountPasswordFile, got %v", loadError)
	}
}
