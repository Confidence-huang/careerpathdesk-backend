/*
运营审计查询合同：通过真实 PostgreSQL 随机 schema 冻结老板可见的最小审计投影。
测试只跨越未来 Commands.ListAuditEvents 公开 interface；metadata 中的业务材料只用于证明查询不会返回它。
调用示例：page, err := commands.ListAuditEvents(ctx, owner, AuditQuery{Limit: 30})。
*/
package operations

import (
	"context"       // 驱动公开审计查询和 synthetic 事实写入。
	"encoding/json" // 从公开 JSON 投影证明没有 metadata 或业务正文。
	"errors"        // 比较不包含过滤值或数据库正文的稳定失败。
	"fmt"           // 生成顺序清晰的 synthetic 审计身份。
	"reflect"       // 精确比较公开字段集合，阻止接口静默扩大。
	"sort"          // 固定字段名顺序供可读失败反馈。
	"strings"       // 构造超过固定过滤字段上限的输入。
	"testing"       // 组织独立审计查询行为。
	"time"          // 建立可重复的 UTC 审计发生时间。

	"github.com/jackc/pgx/v5" // 在随机 schema 内建立最小审计事实。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"        // 使用认证模块已经验证的老板投影。
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 建立并清理独立 synthetic PostgreSQL schema。
)

var syntheticAuditBaseTime = time.Date(2026, time.August, 6, 0, 0, 0, 0, time.UTC) // 所有分页与字段测试共享固定 UTC 起点。

// --- 老板只取得固定最小审计字段 ---
func TestAuditListReturnsOnlyMinimalFields(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 本行为拥有独立 migration、seed 和随机 schema。
	insertSyntheticAudit(t, connection, syntheticAudit{
		ID: "AU-syntheticauditminimal01", ActorKind: "account", ActorID: "A-syntheticstaff01",
		Action: "student.updated", ObjectType: "student", ObjectID: "S-syntheticstudent01",
		Outcome: "success", RequestID: "R-syntheticauditminimal01", OccurredAt: syntheticAuditBaseTime,
		Metadata: `{"version":2,"business_body":"synthetic-private-marker","phone":"synthetic-private-marker","answers":{"q":"o"}}`,
	})
	commands, createError := NewCommands(connection)
	if createError != nil {
		t.Fatalf("audit commands failed to initialize: %v", createError)
	}
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"} // 审计读取只属于当前有效老板。

	page, listError := commands.ListAuditEvents(context.Background(), owner, AuditQuery{Limit: 30})
	if listError != nil || len(page.Events) != 1 {
		t.Fatalf("owner audit list failed: count=%d error=%v", len(page.Events), listError)
	}
	event := page.Events[0]
	if event.ID != "AU-syntheticauditminimal01" || event.ActorKind != "account" || event.ActorID != "A-syntheticstaff01" ||
		event.Action != "student.updated" || event.ObjectType != "student" || event.ObjectID != "S-syntheticstudent01" ||
		event.Outcome != "success" || event.RequestID != "R-syntheticauditminimal01" || !event.OccurredAt.Equal(syntheticAuditBaseTime) {
		t.Fatalf("audit projection changed a minimal fact: %#v", event)
	}
	encoded, encodeError := json.Marshal(event) // JSON 是 HTTP adapter 后续可直接使用的公开投影。
	if encodeError != nil {
		t.Fatal("audit projection could not be encoded")
	}
	publicFields := map[string]json.RawMessage{}
	if decodeError := json.Unmarshal(encoded, &publicFields); decodeError != nil {
		t.Fatal("audit projection did not encode as an object")
	}
	fieldNames := make([]string, 0, len(publicFields))
	for fieldName := range publicFields { // 只比较字段身份，不输出任何字段正文。
		fieldNames = append(fieldNames, fieldName)
	}
	sort.Strings(fieldNames)
	expectedFields := []string{"action", "actor_id", "actor_kind", "id", "object_id", "object_type", "occurred_at", "outcome", "request_id"}
	if !reflect.DeepEqual(fieldNames, expectedFields) {
		t.Fatalf("audit projection exposed a non-minimal field set: %#v", fieldNames)
	}
}

// --- 员工在过滤或游标解析前被拒绝，已停用老板也不能读取 ---
func TestAuditListRequiresCurrentOwnerBeforeQueryDetails(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 权限行为不共享其他审计事实。
	commands, createError := NewCommands(connection)
	if createError != nil {
		t.Fatalf("audit commands failed to initialize: %v", createError)
	}
	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID} // 员工投影不能升级为团队审计权限。
	invalidQuery := AuditQuery{Action: string(make([]byte, 81)), Limit: 0, Cursor: "not-a-valid-cursor"}             // 未授权请求携带无效详情，证明角色门禁先行。

	if _, staffError := commands.ListAuditEvents(context.Background(), staff, invalidQuery); !errors.Is(staffError, ErrForbidden) {
		t.Fatalf("staff audit query did not fail role-first: %v", staffError)
	}
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	if _, disableError := connection.Exec(context.Background(), `UPDATE accounts SET state = 'disabled' WHERE id = $1`, owner.ID); disableError != nil {
		t.Fatal("synthetic owner disable failed")
	}
	if _, disabledError := commands.ListAuditEvents(context.Background(), owner, AuditQuery{Limit: 30}); !errors.Is(disabledError, ErrForbidden) {
		t.Fatalf("disabled owner projection remained able to read audits: %v", disabledError)
	}
}

// --- 审计只支持 action 与 object_type 的精确固定过滤 ---
func TestAuditListAppliesExactFixedFilters(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 固定过滤事实全部位于本测试 schema。
	filterFacts := []syntheticAudit{
		{ID: "AU-syntheticauditfilter01", ActorKind: "account", ActorID: "A-syntheticstaff01", Action: "student.updated", ObjectType: "student", ObjectID: "S-syntheticstudent01", Outcome: "success", RequestID: "R-syntheticauditfilter01", OccurredAt: syntheticAuditBaseTime.Add(time.Minute), Metadata: `{}`},
		{ID: "AU-syntheticauditfilter02", ActorKind: "account", ActorID: "A-syntheticstaff01", Action: "student.created", ObjectType: "student", ObjectID: "S-syntheticstudent02", Outcome: "success", RequestID: "R-syntheticauditfilter02", OccurredAt: syntheticAuditBaseTime.Add(2 * time.Minute), Metadata: `{}`},
		{ID: "AU-syntheticauditfilter03", ActorKind: "account", ActorID: "A-syntheticowner01", Action: "account.updated", ObjectType: "account", ObjectID: "A-syntheticstaff01", Outcome: "success", RequestID: "R-syntheticauditfilter03", OccurredAt: syntheticAuditBaseTime.Add(3 * time.Minute), Metadata: `{}`},
	}
	for _, fact := range filterFacts { // 每条动作/对象组合都可被独立命中或排除。
		insertSyntheticAudit(t, connection, fact)
	}
	commands, createError := NewCommands(connection)
	if createError != nil {
		t.Fatalf("audit commands failed to initialize: %v", createError)
	}
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}

	actionPage, actionError := commands.ListAuditEvents(context.Background(), owner, AuditQuery{Action: "student.updated", Limit: 30})
	if actionError != nil || len(actionPage.Events) != 1 || actionPage.Events[0].ID != "AU-syntheticauditfilter01" {
		t.Fatalf("exact action filter returned the wrong facts: count=%d error=%v", len(actionPage.Events), actionError)
	}
	objectPage, objectError := commands.ListAuditEvents(context.Background(), owner, AuditQuery{ObjectType: "student", Limit: 30})
	if objectError != nil || len(objectPage.Events) != 2 {
		t.Fatalf("exact object filter returned the wrong count: count=%d error=%v", len(objectPage.Events), objectError)
	}
	combinedPage, combinedError := commands.ListAuditEvents(context.Background(), owner, AuditQuery{Action: "student.created", ObjectType: "student", Limit: 30})
	if combinedError != nil || len(combinedPage.Events) != 1 || combinedPage.Events[0].ID != "AU-syntheticauditfilter02" {
		t.Fatalf("combined fixed filters returned the wrong facts: count=%d error=%v", len(combinedPage.Events), combinedError)
	}
	literalPage, literalError := commands.ListAuditEvents(context.Background(), owner, AuditQuery{Action: "student.%", Limit: 30})
	if literalError != nil || len(literalPage.Events) != 0 { // 通配符文本必须作为普通动作值处理，不能扩大查询。
		t.Fatalf("action filter accepted pattern semantics: count=%d error=%v", len(literalPage.Events), literalError)
	}

	invalidQueries := []AuditQuery{
		{Action: strings.Repeat("a", 81), Limit: 30},     // action 遵循 OpenAPI 的 80 字符上限。
		{ObjectType: strings.Repeat("o", 41), Limit: 30}, // object_type 遵循 OpenAPI 的 40 字符上限。
		{Limit: 0},   // 页大小不能隐式变成无界查询。
		{Limit: 101}, // 页大小不得超过统一列表上限。
		{Limit: 30, Cursor: "not-a-valid-cursor"}, // 客户端不能构造任意数据库边界。
	}
	for _, query := range invalidQueries { // 每种非法查询都收敛为同一个稳定输入错误。
		if _, queryError := commands.ListAuditEvents(context.Background(), owner, query); !errors.Is(queryError, ErrInvalidInput) {
			t.Fatalf("invalid audit query did not fail closed: %v", queryError)
		}
	}
}

// --- 同时刻审计使用 ID 决胜且新增头部不会扰动后续页 ---
func TestAuditCursorRemainsStableAcrossTiedTimesAndNewHead(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 游标行为从一个独立的五行时间切片开始。
	for index := 1; index <= 5; index++ {
		identity := fmt.Sprintf("AU-syntheticauditcursor%02d", index) // ID 的字典序就是同时刻的稳定次序。
		insertSyntheticAudit(t, connection, syntheticAudit{
			ID: identity, ActorKind: "account", ActorID: "A-syntheticstaff01",
			Action: "student.updated", ObjectType: "student", ObjectID: "S-syntheticstudent01",
			Outcome: "success", RequestID: fmt.Sprintf("R-syntheticauditcursor%02d", index),
			OccurredAt: syntheticAuditBaseTime, Metadata: `{}`,
		})
	}
	commands, createError := NewCommands(connection)
	if createError != nil {
		t.Fatalf("audit commands failed to initialize: %v", createError)
	}
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}

	firstPage, firstError := commands.ListAuditEvents(context.Background(), owner, AuditQuery{Action: "student.updated", Limit: 2})
	if firstError != nil || !reflect.DeepEqual(auditEventIDs(firstPage), []string{"AU-syntheticauditcursor05", "AU-syntheticauditcursor04"}) || firstPage.NextCursor == nil {
		t.Fatalf("first audit page was not stably ordered: ids=%#v cursor=%t error=%v", auditEventIDs(firstPage), firstPage.NextCursor != nil, firstError)
	}
	if len(*firstPage.NextCursor) > 512 { // 游标遵循协议上限且不会变成无界客户端状态。
		t.Fatal("audit cursor exceeded its public size limit")
	}
	insertSyntheticAudit(t, connection, syntheticAudit{
		ID: "AU-syntheticauditcursor06", ActorKind: "account", ActorID: "A-syntheticstaff01",
		Action: "student.updated", ObjectType: "student", ObjectID: "S-syntheticstudent01",
		Outcome: "success", RequestID: "R-syntheticauditcursor06", OccurredAt: syntheticAuditBaseTime, Metadata: `{}`,
	}) // 第一页之后的新头部事实不得造成旧页重复或跳过。

	secondPage, secondError := commands.ListAuditEvents(context.Background(), owner, AuditQuery{Action: "student.updated", Limit: 2, Cursor: *firstPage.NextCursor})
	if secondError != nil || !reflect.DeepEqual(auditEventIDs(secondPage), []string{"AU-syntheticauditcursor03", "AU-syntheticauditcursor02"}) || secondPage.NextCursor == nil {
		t.Fatalf("second audit page drifted after a new head insert: ids=%#v cursor=%t error=%v", auditEventIDs(secondPage), secondPage.NextCursor != nil, secondError)
	}
	thirdPage, thirdError := commands.ListAuditEvents(context.Background(), owner, AuditQuery{Action: "student.updated", Limit: 2, Cursor: *secondPage.NextCursor})
	if thirdError != nil || !reflect.DeepEqual(auditEventIDs(thirdPage), []string{"AU-syntheticauditcursor01"}) || thirdPage.NextCursor != nil {
		t.Fatalf("final audit page duplicated, skipped or invented facts: ids=%#v cursor=%t error=%v", auditEventIDs(thirdPage), thirdPage.NextCursor != nil, thirdError)
	}
}

// --- 提取一页审计的不透明身份供稳定顺序断言 ---
func auditEventIDs(page AuditPage) []string {
	identities := make([]string, 0, len(page.Events)) // 只收集非敏感审计 ID，不接触字段正文。
	for _, event := range page.Events {
		identities = append(identities, event.ID) // 保留公开返回顺序以验证游标合同。
	}
	return identities
}

// syntheticAudit 是测试写入 audit_events 所需的完整受控事实；Metadata 永不成为公开返回值。
type syntheticAudit struct {
	ID         string    // ID 在相同时间下提供稳定次序。
	ActorKind  string    // ActorKind 区分账号或受限邀请来源。
	ActorID    string    // ActorID 保留历史逐人归属。
	Action     string    // Action 是固定业务动作码。
	ObjectType string    // ObjectType 是固定业务对象种类。
	ObjectID   string    // ObjectID 是不透明对象引用。
	Outcome    string    // Outcome 是固定最小结果码。
	RequestID  string    // RequestID 关联一次安全请求反馈。
	OccurredAt time.Time // OccurredAt 是数据库可比较的 UTC 时间。
	Metadata   string    // Metadata 只在数据库中证明查询投影不会复制业务材料。
}

// --- 写入一条独立合成审计事实 ---
func insertSyntheticAudit(t *testing.T, connection *pgx.Conn, event syntheticAudit) {
	t.Helper() // 夹具错误归因到调用行为测试。
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO audit_events (
			id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)`,
		event.ID, event.ActorKind, event.ActorID, event.Action, event.ObjectType, event.ObjectID,
		event.Outcome, event.RequestID, event.Metadata, event.OccurredAt.UTC()); insertError != nil {
		t.Fatal("synthetic audit insertion failed")
	}
}
