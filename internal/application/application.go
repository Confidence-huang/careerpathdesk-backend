/*
应用组合根：把一个已验证配置装配成唯一 CareerPathDesk HTTP handler。
领域包只依赖自己的命令；API 与本地 UAT 入口共同复用本组合，避免出现第二套授权或事务行为。
*/
package application

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/confidence-huang/careerpathdesk-backend/internal/accounts"
	"github.com/confidence-huang/careerpathdesk-backend/internal/assessments"
	"github.com/confidence-huang/careerpathdesk-backend/internal/attention"
	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/followups"
	"github.com/confidence-huang/careerpathdesk-backend/internal/invitations"
	"github.com/confidence-huang/careerpathdesk-backend/internal/operations"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/clock"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/identity"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/postgres"
	applicationruntime "github.com/confidence-huang/careerpathdesk-backend/internal/platform/runtime"
	"github.com/confidence-huang/careerpathdesk-backend/internal/privacy"
	"github.com/confidence-huang/careerpathdesk-backend/internal/students"
	"github.com/confidence-huang/careerpathdesk-backend/internal/teamplan" // 装配工作台唯一团队计划。
)

var ErrSchemaUnavailable = errors.New("application schema is unavailable")

type Application struct {
	Handler http.Handler
	pool    *postgres.Pool
}

func Open(ctx context.Context, configuration config.Config, version string) (*Application, error) {
	utcClock := clock.System{}
	privacyNotice, noticeError := privacy.LoadNotice(
		configuration.RuntimeMode, configuration.PrivacyNoticeFile, version, utcClock.Now(),
	) // 在接触数据库前验证 production 审批文件与当前完整发布 SHA 的绑定。
	if noticeError != nil {
		return nil, noticeError
	}
	privacyNoticeHTTP, noticeHTTPError := privacy.NewNoticeHTTP(privacyNotice) // 冻结请求期间不再读取文件的匿名公开投影。
	if noticeHTTPError != nil {
		return nil, noticeHTTPError
	}
	connectionPool, connectError := postgres.OpenPool(ctx, configuration.Database)
	if connectError != nil {
		return nil, connectError
	}
	fail := func(openError error) (*Application, error) {
		connectionPool.Close()
		return nil, openError
	}
	if schemaError := requireSchema(ctx, connectionPool, configuration.ExpectedSchemaVersion); schemaError != nil {
		return fail(schemaError)
	}

	sessions, commandError := auth.NewSessionCommands(connectionPool, utcClock.Now)
	if commandError != nil {
		return fail(commandError)
	}
	keys, keyError := auth.LoadAccessTokenKeys(configuration.AccessTokenPrivateKeyFile)
	if keyError != nil {
		return fail(keyError)
	}
	tokens, tokenError := auth.NewAccessTokens(keys, utcClock.Now, func() (string, error) { return identity.New("JTI") })
	if tokenError != nil {
		return fail(tokenError)
	}
	var mfaEncryptionKey []byte
	if configuration.RequireMFA {
		mfaEncryptionKey, commandError = auth.LoadMFAEncryptionKey(configuration.MFAEncryptionKeyFile)
		if commandError != nil {
			return fail(commandError)
		}
	}
	mfaCommands, commandError := auth.NewMFACommands(connectionPool, sessions, utcClock.Now, configuration.RequireMFA, mfaEncryptionKey)
	if commandError != nil {
		return fail(commandError)
	}
	authentication, httpError := auth.NewHTTPWithMFA(sessions, tokens, mfaCommands)
	if httpError != nil {
		return fail(httpError)
	}

	accountCommands, commandError := accounts.NewCommands(connectionPool, utcClock.Now, identity.New)
	if commandError != nil {
		return fail(commandError)
	}
	accountHTTP, httpError := accounts.NewHTTP(accountCommands, authentication.CurrentAccount)
	if httpError != nil {
		return fail(httpError)
	}
	studentCommands, commandError := students.NewCommands(connectionPool, utcClock.Now, identity.New)
	if commandError != nil {
		return fail(commandError)
	}
	studentHTTP, httpError := students.NewHTTP(studentCommands, authentication.CurrentAccount)
	if httpError != nil {
		return fail(httpError)
	}
	followUpCommands, commandError := followups.NewCommands(connectionPool, utcClock.Now, identity.New)
	if commandError != nil {
		return fail(commandError)
	}
	followUpHTTP, httpError := followups.NewHTTP(followUpCommands, authentication.CurrentAccount)
	if httpError != nil {
		return fail(httpError)
	}
	attentionCommands, commandError := attention.NewCommands(connectionPool, utcClock.Now, identity.New)
	if commandError != nil {
		return fail(commandError)
	}
	attentionHTTP, httpError := attention.NewHTTP(attentionCommands, authentication.CurrentAccount)
	if httpError != nil {
		return fail(httpError)
	}
	invitationCommands, commandError := invitations.NewCommands(connectionPool, utcClock.Now, identity.New, func() (string, error) { return identity.New("SEC") })
	if commandError != nil {
		return fail(commandError)
	}
	invitationHTTP, httpError := invitations.NewHTTP(invitationCommands, authentication.CurrentAccount, configuration.PublicOrigin)
	if httpError != nil {
		return fail(httpError)
	}
	assessmentCommands, commandError := assessments.NewCommands(connectionPool, utcClock.Now, identity.New)
	if commandError != nil {
		return fail(commandError)
	}
	assessmentHTTP, httpError := assessments.NewHTTP(invitationCommands, assessmentCommands)
	if httpError != nil {
		return fail(httpError)
	}
	operationCommands, commandError := operations.NewCommands(connectionPool, utcClock.Now)
	if commandError != nil {
		return fail(commandError)
	}
	operationHTTP, httpError := operations.NewHTTP(operationCommands, authentication.CurrentAccountSession)
	if httpError != nil {
		return fail(httpError)
	}
	teamPlanCommands, commandError := teamplan.NewCommands(connectionPool, identity.New)
	if commandError != nil {
		return fail(commandError)
	}
	teamPlanHTTP, httpError := teamplan.NewHTTP(teamPlanCommands, authentication.CurrentAccount)
	if httpError != nil {
		return fail(httpError)
	}
	privacyRequestCommands, commandError := privacy.NewRequestCommands(connectionPool, utcClock.Now, identity.New)
	if commandError != nil {
		return fail(commandError)
	}
	privacyRequestHTTP, httpError := privacy.NewHTTP(privacyRequestCommands, authentication.CurrentAccount)
	if httpError != nil {
		return fail(httpError)
	}

	handler := applicationruntime.NewRouter(
		applicationruntime.BuildInfo{Version: version},
		applicationruntime.Readiness{Database: connectionPool.Ping},
		httpx.SecurityConfig{PublicOrigin: configuration.PublicOrigin},
		func(api *gin.RouterGroup) {
			authentication.Register(api)
			accountHTTP.Register(api)
			studentHTTP.Register(api)
			followUpHTTP.Register(api)
			attentionHTTP.Register(api)
			invitationHTTP.Register(api)
			assessmentHTTP.Register(api)
			operationHTTP.Register(api)
			teamPlanHTTP.Register(api)
			privacyNoticeHTTP.Register(api)
			privacyRequestHTTP.Register(api)
		},
	)
	return &Application{Handler: handler, pool: connectionPool}, nil
}

func (application *Application) Close() {
	if application != nil && application.pool != nil {
		application.pool.Close()
	}
}

func requireSchema(ctx context.Context, pool *postgres.Pool, expected int64) error {
	var count int
	var maximum int64
	queryError := pool.QueryRow(ctx, "SELECT count(*)::integer, COALESCE(max(version), 0) FROM schema_migrations").Scan(&count, &maximum)
	if queryError != nil || maximum != expected || count != int(expected) {
		return ErrSchemaUnavailable
	}
	return nil
}
