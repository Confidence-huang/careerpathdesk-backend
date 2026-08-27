/*
一次性生产老板初始化：在当前精确 schema 空账号库中创建唯一 owner 和最小审计事实。
该深模块不读取命令行或文件；调用方只把已验证的一次性输入交入单个 PostgreSQL 事务。
*/
package bootstrap

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"
)

var ErrInvalidDependencies = errors.New("owner bootstrap dependencies are invalid")
var ErrInvalidInput = errors.New("owner bootstrap input is invalid")
var ErrSchemaMismatch = errors.New("owner bootstrap requires exact schema")
var ErrAlreadyInitialized = errors.New("owner bootstrap is permanently closed")
var ErrWriteFailed = errors.New("owner bootstrap write failed")

const ownerBootstrapAdvisoryLock int64 = 0x5031374f574e4552 // 固定 “P17OWNER” 锁只串行化同一数据库内的首次老板创建。

type Input struct {
	Username    string
	DisplayName string
	Password    string
}

type Result struct {
	AccountID string
}

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error)
}

type Commands struct {
	database    transactionSource
	newIdentity func(string) (string, error)
}

type preparedOwner struct {
	accountID          string
	auditID            string
	usernameDisplay    string
	usernameNormalized string
	displayName        string
	passwordHash       string
}

func New(database transactionSource, newIdentity func(string) (string, error)) (*Commands, error) {
	if database == nil || newIdentity == nil {
		return nil, ErrInvalidDependencies
	}
	return &Commands{database: database, newIdentity: newIdentity}, nil
}

// Bootstrap 将 advisory lock、空账号断言、账号和审计绑定到同一提交结果。
func (commands *Commands) Bootstrap(ctx context.Context, input Input) (Result, error) {
	prepared, prepareError := commands.prepare(input)
	if prepareError != nil {
		return Result{}, prepareError
	}
	transaction, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return Result{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, lockError := transaction.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ownerBootstrapAdvisoryLock); lockError != nil {
		return Result{}, ErrWriteFailed
	}
	if schemaError := requireExactSchema(ctx, transaction); schemaError != nil {
		return Result{}, schemaError
	}
	var accountCount int64
	if countError := transaction.QueryRow(ctx, `SELECT count(*) FROM accounts`).Scan(&accountCount); countError != nil {
		return Result{}, ErrWriteFailed
	}
	if accountCount != 0 {
		return Result{}, ErrAlreadyInitialized
	}
	if _, insertError := transaction.Exec(ctx, `
		INSERT INTO accounts (
			id, username_normalized, username_display, display_name, password_hash,
			role, state, staff_profile_id, credential_version, must_change_password, version
		) VALUES ($1, $2, $3, $4, $5, 'owner', 'active', NULL, 1, true, 1)`,
		prepared.accountID, prepared.usernameNormalized, prepared.usernameDisplay, prepared.displayName, prepared.passwordHash,
	); insertError != nil {
		return Result{}, ErrWriteFailed
	}
	if _, auditError := transaction.Exec(ctx, `
		INSERT INTO audit_events (
			id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata
		) VALUES ($1, 'system', 'bootstrap-owner', 'account.bootstrap_owner', 'account', $2, 'success', 'bootstrap-owner', '{}'::jsonb)`,
		prepared.auditID, prepared.accountID,
	); auditError != nil {
		return Result{}, ErrWriteFailed
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Result{}, ErrWriteFailed
	}
	return Result{AccountID: prepared.accountID}, nil
}

func (commands *Commands) prepare(input Input) (preparedOwner, error) {
	usernameDisplay := norm.NFKC.String(strings.TrimSpace(input.Username))
	usernameNormalized := cases.Fold().String(usernameDisplay)
	displayName := norm.NFKC.String(strings.TrimSpace(input.DisplayName))
	passwordLength := utf8.RuneCountInString(input.Password)
	if !validText(usernameDisplay, 1, 128) || !validText(usernameNormalized, 1, 128) || !validText(displayName, 1, 80) || !utf8.ValidString(input.Password) || passwordLength < 14 || passwordLength > 128 {
		return preparedOwner{}, ErrInvalidInput
	}
	passwordHash, hashError := auth.HashPassword(input.Password)
	if hashError != nil {
		return preparedOwner{}, ErrInvalidInput
	}
	accountID, accountIdentityError := commands.newIdentity("A")
	auditID, auditIdentityError := commands.newIdentity("AU")
	if accountIdentityError != nil || auditIdentityError != nil || !validIdentity(accountID, "A") || !validIdentity(auditID, "AU") {
		return preparedOwner{}, ErrWriteFailed
	}
	return preparedOwner{
		accountID: accountID, auditID: auditID, usernameDisplay: usernameDisplay,
		usernameNormalized: usernameNormalized, displayName: displayName, passwordHash: passwordHash,
	}, nil
}

func requireExactSchema(ctx context.Context, transaction pgx.Tx) error {
	var count int64
	var minimum int64
	var maximum int64
	queryError := transaction.QueryRow(ctx, `SELECT count(*), COALESCE(min(version), 0), COALESCE(max(version), 0) FROM schema_migrations`).Scan(&count, &minimum, &maximum)
	if queryError != nil {
		return ErrSchemaMismatch
	}
	if count != config.SupportedSchemaVersion || minimum != 1 || maximum != config.SupportedSchemaVersion {
		return ErrSchemaMismatch
	}
	return nil
}

func validText(value string, minimum int, maximum int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= minimum && length <= maximum
}

func validIdentity(value string, prefix string) bool {
	return strings.HasPrefix(value, prefix+"-") && validText(value, len(prefix)+13, len(prefix)+81)
}
