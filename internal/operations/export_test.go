/*
运营导出合同：通过真实 PostgreSQL 随机 schema 冻结老板一次确认、动态会话权限和一致快照。
测试只跨越未来 Commands.CreateExportConfirmation 与 Commands.RunExport 公开 interface；导出正文从不进入失败输出。
调用示例：artifact, err := commands.RunExport(ctx, owner, RunExportInput{SessionID: sessionID, ExportType: "students", Confirmation: value, RequestID: requestID})。
*/
package operations

import (
	"archive/zip"   // 读取生成的 XLSX 容器，验证 WPS 可消费的表格结构。
	"bytes"         // 只比较 synthetic 快照标记是否同属一个版本。
	"context"       // 驱动公开确认、导出和 PostgreSQL 故障夹具。
	"crypto/sha256" // 为合成会话生成不可逆的唯一 digest。
	"errors"        // 比较不含对象、正文或秘密的稳定失败。
	"io"            // 读取 XLSX 内部 XML，但不把导出正文写入测试输出。
	"strings"       // 检查最小审计元数据不含受保护标记。
	"sync"          // 使精确过期时钟可被并发快照测试安全读取。
	"testing"       // 组织独立的导出行为合同。
	"time"          // 冻结精确 UTC 过期边界和并发等待上限。

	"github.com/jackc/pgx/v5" // 建立并发连接、会话事实和可控故障。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"        // 使用认证模块的最小当前账号投影。
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 建立并清理独立 synthetic PostgreSQL schema。
)

const syntheticExportRequestID = "R-syntheticexportrequest01" // 审计查询只使用不含业务内容的固定请求标识。

var syntheticExportBaseTime = time.Date(2026, time.August, 6, 4, 0, 0, 0, time.UTC) // 所有确认与会话边界共享固定 UTC 起点。

// --- 只有数据库当前有效老板能够触发确认或导出 ---
func TestExportRequiresCurrentOwnerBeforeConfirmationDetails(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 本权限行为拥有独立 migration、seed 和随机 schema。
	prepareSyntheticExportIdentities(t, connection)
	clock := newSyntheticExportClock(syntheticExportBaseTime)
	commands, createError := NewCommands(connection, clock.Now)
	if createError != nil {
		t.Fatalf("export commands failed to initialize: %v", createError)
	}
	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	invalidConfirmation := ExportConfirmationInput{SessionID: "", ExportType: "not-an-export"} // 角色拒绝必须先于会话和类型细节。

	issued, staffIssueError := commands.CreateExportConfirmation(context.Background(), staff, invalidConfirmation)
	if !errors.Is(staffIssueError, ErrForbidden) || issued.Confirmation != "" || !issued.ExpiresAt.IsZero() {
		t.Fatalf("staff export confirmation did not fail role-first: issued=%t error=%v", issued.Confirmation != "", staffIssueError)
	}
	artifact, staffExportError := commands.RunExport(context.Background(), staff, RunExportInput{
		SessionID: "", ExportType: "not-an-export", Confirmation: "synthetic-unknown-confirmation", RequestID: "bad",
	})
	if !errors.Is(staffExportError, ErrForbidden) {
		t.Fatalf("staff export did not fail role-first: %v", staffExportError)
	}
	requireEmptyExportArtifact(t, artifact)

	forgedOwner := auth.Account{ID: "A-syntheticstaff01", Role: "owner", State: "active"} // 调用方投影不能将员工升级为老板。
	_, forgedError := commands.CreateExportConfirmation(context.Background(), forgedOwner, ExportConfirmationInput{
		SessionID: "AS-syntheticexportstaff01", ExportType: "students",
	})
	if !errors.Is(forgedError, ErrForbidden) {
		t.Fatalf("database staff role trusted a forged owner projection: %v", forgedError)
	}

	owner := syntheticExportOwner("A-syntheticowner01")
	if _, disableError := connection.Exec(context.Background(), `UPDATE accounts SET state = 'disabled' WHERE id = $1`, owner.ID); disableError != nil {
		t.Fatal("synthetic export owner disable failed")
	}
	_, disabledError := commands.CreateExportConfirmation(context.Background(), owner, ExportConfirmationInput{
		SessionID: "AS-syntheticexportowner01", ExportType: "students",
	})
	if !errors.Is(disabledError, ErrForbidden) {
		t.Fatalf("disabled owner projection remained able to confirm exports: %v", disabledError)
	}
}

// --- 学生导出使用带中文表头和阅读布局的 XLSX ---
func TestStudentExportUsesReadableChineseWorkbook(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations")   // 真实查询确保布局验证覆盖完整学生导出链路。
	prepareSyntheticExportIdentities(t, connection)           // 当前老板和会话仍通过正式一次确认门禁。
	clock := newSyntheticExportClock(syntheticExportBaseTime) // 固定时钟避免确认期限受测试耗时影响。
	commands, createError := NewCommands(connection, clock.Now)
	if createError != nil {
		t.Fatalf("export commands failed to initialize: %v", createError)
	}
	owner := syntheticExportOwner("A-syntheticowner01")                                         // 只使用固定合成老板投影。
	issued := issueSyntheticExport(t, commands, owner, "AS-syntheticexportowner01", "students") // 通过公开接口取得一次确认。

	artifact, exportError := commands.RunExport(context.Background(), owner, RunExportInput{
		SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID,
	})
	if exportError != nil {
		t.Fatalf("student workbook export failed: %v", exportError)
	}
	if artifact.MediaType != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
		t.Fatalf("student export did not use a width-aware workbook: %s", artifact.MediaType)
	}
	workbookXML, worksheetXML := readSyntheticWorkbookXML(t, artifact.Body) // 只读取结构文本，不输出学生单元格正文。
	for _, header := range []string{"学生编号", "姓名", "现居地", "主负责人", "协作老师", "下一步行动"} {
		if !strings.Contains(workbookXML, header) {
			t.Fatalf("student workbook is missing Chinese header %q", header)
		}
	}
	for _, businessText := range []string{"学生资料", "系统信息", "员工录入", "Synthetic Coach One"} {
		if !strings.Contains(workbookXML, businessText) {
			t.Fatalf("student workbook is missing readable business text %q", businessText)
		}
	}
	for _, layoutMarker := range []string{"<cols>", " width=", "state=\"frozen\"", "<autoFilter"} {
		if !strings.Contains(worksheetXML, layoutMarker) {
			t.Fatalf("student workbook is missing readable layout marker %q", layoutMarker)
		}
	}
}

// --- 其余导出类型也保持中文工作簿合同 ---
func TestFollowUpAndAssessmentExportsUseChineseWorkbooks(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations")   // 同一随机 schema 足以生成两个互不重放的确认。
	prepareSyntheticExportIdentities(t, connection)           // 所有导出仍要求当前有效老板会话。
	clock := newSyntheticExportClock(syntheticExportBaseTime) // 两次导出共享固定未过期时刻。
	commands, createError := NewCommands(connection, clock.Now)
	if createError != nil {
		t.Fatalf("export commands failed to initialize: %v", createError)
	}
	owner := syntheticExportOwner("A-syntheticowner01") // 公开账号投影不携带文件内容。
	exports := []struct {
		exportType string // exportType 选择服务端固定工作簿注册表。
		sheetName  string // sheetName 是打开文件时看到的中文页签。
		header     string // header 是每张表的第一个中文列名。
	}{
		{exportType: "follow-ups", sheetName: "跟进记录", header: "跟进编号"},
		{exportType: "assessments", sheetName: "测评结果", header: "测评编号"},
	}
	for _, expected := range exports {
		issued := issueSyntheticExport(t, commands, owner, "AS-syntheticexportowner01", expected.exportType) // 每种类型独立确认。
		artifact, exportError := commands.RunExport(context.Background(), owner, RunExportInput{
			SessionID: "AS-syntheticexportowner01", ExportType: expected.exportType, Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID,
		})
		if exportError != nil || artifact.MediaType != exportMediaType {
			t.Fatalf("%s workbook export failed: %v", expected.exportType, exportError)
		}
		workbookXML, worksheetXML := readSyntheticWorkbookXML(t, artifact.Body) // 只检查固定中文结构。
		if !strings.Contains(workbookXML, expected.sheetName) || !strings.Contains(workbookXML, expected.header) {
			t.Fatalf("%s workbook is missing its Chinese sheet or header", expected.exportType)
		}
		if !strings.Contains(worksheetXML, "<cols>") || !strings.Contains(worksheetXML, "<autoFilter") {
			t.Fatalf("%s workbook is missing readable column widths or filters", expected.exportType)
		}
	}
}

// --- 确认严格绑定当前账号、当前会话和一个导出类型 ---
func TestExportConfirmationBindsAccountSessionAndTypeAndRejectsReplay(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 绑定失败不共享其他确认状态。
	prepareSyntheticExportIdentities(t, connection)
	clock := newSyntheticExportClock(syntheticExportBaseTime)
	commands, createError := NewCommands(connection, clock.Now)
	if createError != nil {
		t.Fatalf("export commands failed to initialize: %v", createError)
	}
	owner := syntheticExportOwner("A-syntheticowner01")
	issued := issueSyntheticExport(t, commands, owner, "AS-syntheticexportowner01", "students")
	if len(issued.Confirmation) < 32 || !issued.ExpiresAt.After(clock.Now()) { // 公开值必须高熵且明确短期终点。
		t.Fatal("export confirmation did not expose a bounded one-time value")
	}

	wrongAttempts := []struct {
		actor auth.Account   // actor 改变账号绑定或保持原账号。
		input RunExportInput // input 只改变会话、类型或确认值。
	}{
		{syntheticExportOwner("A-syntheticowner02"), RunExportInput{SessionID: "AS-syntheticexportowner02", ExportType: "students", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID}},
		{owner, RunExportInput{SessionID: "AS-syntheticexportowner03", ExportType: "students", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID}},
		{owner, RunExportInput{SessionID: "AS-syntheticexportowner01", ExportType: "follow-ups", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID}},
		{owner, RunExportInput{SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: "synthetic-unknown-confirmation", RequestID: syntheticExportRequestID}},
	}
	for _, attempt := range wrongAttempts { // 账号、会话、类型和未知值共享一个不可枚举失败。
		artifact, exportError := commands.RunExport(context.Background(), attempt.actor, attempt.input)
		if !errors.Is(exportError, ErrExportConfirmationUnavailable) {
			t.Fatalf("misbound export confirmation exposed a distinct failure: %v", exportError)
		}
		requireEmptyExportArtifact(t, artifact)
	}

	artifact, exportError := commands.RunExport(context.Background(), owner, RunExportInput{
		SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID,
	})
	if exportError != nil || artifact.MediaType != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" || len(artifact.Body) == 0 {
		t.Fatalf("correctly bound export did not return its fixed public shape: body=%t error=%v", len(artifact.Body) != 0, exportError)
	}
	replayedArtifact, replayError := commands.RunExport(context.Background(), owner, RunExportInput{
		SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID,
	})
	if !errors.Is(replayError, ErrExportConfirmationUnavailable) {
		t.Fatalf("used export confirmation did not reject replay: %v", replayError)
	}
	requireEmptyExportArtifact(t, replayedArtifact)
}

// --- 过期边界前最后一刻可用，到达边界立即失效 ---
func TestExportConfirmationUsesAnExactExpiryBoundary(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 可注入时钟让边界不依赖宿主调度。
	prepareSyntheticExportIdentities(t, connection)
	clock := newSyntheticExportClock(syntheticExportBaseTime)
	commands, createError := NewCommands(connection, clock.Now)
	if createError != nil {
		t.Fatalf("export commands failed to initialize: %v", createError)
	}
	owner := syntheticExportOwner("A-syntheticowner01")

	lastInstant := issueSyntheticExport(t, commands, owner, "AS-syntheticexportowner01", "students")
	clock.Set(lastInstant.ExpiresAt.Add(-time.Nanosecond)) // 到期前的最后可比较时刻仍属于已确认意图。
	artifact, beforeBoundaryError := commands.RunExport(context.Background(), owner, RunExportInput{
		SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: lastInstant.Confirmation, RequestID: syntheticExportRequestID,
	})
	if beforeBoundaryError != nil || len(artifact.Body) == 0 {
		t.Fatalf("export confirmation expired before its exact boundary: body=%t error=%v", len(artifact.Body) != 0, beforeBoundaryError)
	}

	clock.Set(syntheticExportBaseTime)
	exactBoundary := issueSyntheticExport(t, commands, owner, "AS-syntheticexportowner01", "students")
	clock.Set(exactBoundary.ExpiresAt) // 等于 expires_at 就是过期，不额外放行一个时钟粒度。
	expiredArtifact, expiredError := commands.RunExport(context.Background(), owner, RunExportInput{
		SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: exactBoundary.Confirmation, RequestID: syntheticExportRequestID,
	})
	if !errors.Is(expiredError, ErrExportConfirmationUnavailable) {
		t.Fatalf("export confirmation remained valid at its expiry boundary: %v", expiredError)
	}
	requireEmptyExportArtifact(t, expiredArtifact)
}

// --- 确认发出后仍重新校验账号、会话和凭据版本 ---
func TestExportDynamicallyRevalidatesAccountAndSession(t *testing.T) {
	tests := []struct {
		name   string                                             // name 说明哪一个动态安全事实变化。
		change func(*testing.T, *pgx.Conn, *syntheticExportClock) // change 只改变已发出确认后的权威事实。
	}{
		{"account disabled", func(test *testing.T, connection *pgx.Conn, _ *syntheticExportClock) {
			if _, changeError := connection.Exec(context.Background(), `UPDATE accounts SET state = 'disabled' WHERE id = 'A-syntheticowner01'`); changeError != nil {
				test.Fatal("synthetic export account disable failed")
			}
		}},
		{"session revoked", func(test *testing.T, connection *pgx.Conn, clock *syntheticExportClock) {
			if _, changeError := connection.Exec(context.Background(), `
				UPDATE account_sessions SET revoked_at = $2, revoke_reason = 'self_revoked' WHERE id = $1`,
				"AS-syntheticexportowner01", clock.Now()); changeError != nil {
				test.Fatal("synthetic export session revoke failed")
			}
		}},
		{"credential version changed", func(test *testing.T, connection *pgx.Conn, _ *syntheticExportClock) {
			if _, changeError := connection.Exec(context.Background(), `UPDATE accounts SET credential_version = credential_version + 1 WHERE id = 'A-syntheticowner01'`); changeError != nil {
				test.Fatal("synthetic export credential change failed")
			}
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(test *testing.T) {
			connection := testsupport.OpenDatabase(test, "operations") // 每种终态拥有独立 schema 和确认。
			prepareSyntheticExportIdentities(test, connection)
			clock := newSyntheticExportClock(syntheticExportBaseTime)
			commands, createError := NewCommands(connection, clock.Now)
			if createError != nil {
				test.Fatalf("export commands failed to initialize: %v", createError)
			}
			owner := syntheticExportOwner("A-syntheticowner01")
			issued := issueSyntheticExport(test, commands, owner, "AS-syntheticexportowner01", "students")
			testCase.change(test, connection, clock) // 在确认后改变数据库权威，迫使导出动态复核。

			artifact, exportError := commands.RunExport(context.Background(), owner, RunExportInput{
				SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID,
			})
			if !errors.Is(exportError, ErrForbidden) {
				test.Fatalf("changed account or session remained export-authorized: %v", exportError)
			}
			requireEmptyExportArtifact(test, artifact)
		})
	}
}

// --- 并发修改只能让导出看到完整修改前或完整修改后 ---
func TestExportUsesOneConsistentDatabaseSnapshot(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 主连接执行公开导出命令。
	prepareSyntheticExportIdentities(t, connection)
	clock := newSyntheticExportClock(syntheticExportBaseTime)
	commands, createError := NewCommands(connection, clock.Now)
	if createError != nil {
		t.Fatalf("export commands failed to initialize: %v", createError)
	}
	if _, setupError := connection.Exec(context.Background(), `
		UPDATE students SET name = CASE id
			WHEN 'S-syntheticstudent01' THEN 'Synthetic Snapshot Old Alpha'
			WHEN 'S-syntheticstudent02' THEN 'Synthetic Snapshot Old Beta'
			ELSE name END
		WHERE id IN ('S-syntheticstudent01', 'S-syntheticstudent02')`); setupError != nil {
		t.Fatal("synthetic snapshot baseline failed")
	}
	owner := syntheticExportOwner("A-syntheticowner01")
	issued := issueSyntheticExport(t, commands, owner, "AS-syntheticexportowner01", "students")
	control := openSyntheticExportPeer(t, connection, "synthetic-export-control") // 控制事务锁住确认行，确定首次事务读取的交叉点。
	writer := openSyntheticExportPeer(t, connection, "synthetic-export-writer")   // 写连接原子修改两个可识别标记。
	controlTransaction, lockError := control.Begin(context.Background())
	if lockError != nil {
		t.Fatal("synthetic snapshot control transaction failed")
	}
	controlOpen := true
	defer func() {
		if controlOpen {
			_ = controlTransaction.Rollback(context.Background())
		}
	}() // 任何夹具失败都释放确认行，不遗留阻塞会话。
	confirmationDigest := sha256.Sum256([]byte(issued.Confirmation))
	if _, lockError = controlTransaction.Exec(context.Background(), `
		SELECT confirmation_digest FROM export_confirmations
		WHERE confirmation_digest = $1 FOR UPDATE`, confirmationDigest[:]); lockError != nil {
		t.Fatal("synthetic snapshot confirmation lock failed")
	}
	var exportBackendPID int32
	if pidError := connection.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&exportBackendPID); pidError != nil {
		t.Fatal("synthetic export backend identity unavailable")
	}
	type exportResult struct {
		artifact ExportArtifact // artifact 只在命令成功后传回主测试。
		err      error          // err 只携带稳定分类，不携带正文。
	}
	resultChannel := make(chan exportResult, 1)
	go func() {
		artifact, exportError := commands.RunExport(context.Background(), owner, RunExportInput{
			SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID,
		})
		resultChannel <- exportResult{artifact: artifact, err: exportError}
	}()
	if !waitForSyntheticSnapshotBarrier(control, exportBackendPID) { // 只有本导出首次事务读取已建立快照后才允许并发提交。
		t.Fatal("export did not reach the synthetic snapshot barrier")
	}
	if _, updateError := writer.Exec(context.Background(), `
		UPDATE students SET name = CASE id
			WHEN 'S-syntheticstudent01' THEN 'Synthetic Snapshot New Alpha'
			WHEN 'S-syntheticstudent02' THEN 'Synthetic Snapshot New Beta'
			ELSE name END
		WHERE id IN ('S-syntheticstudent01', 'S-syntheticstudent02')`); updateError != nil {
		t.Fatal("synthetic concurrent snapshot update failed")
	}
	if unlockError := controlTransaction.Commit(context.Background()); unlockError != nil {
		t.Fatal("synthetic snapshot barrier failed to unlock")
	}
	controlOpen = false

	var result exportResult
	select {
	case result = <-resultChannel:
	case <-time.After(5 * time.Second):
		t.Fatal("export did not finish after the snapshot barrier opened")
	}
	if result.err != nil || len(result.artifact.Body) == 0 {
		t.Fatalf("snapshot export failed: body=%t error=%v", len(result.artifact.Body) != 0, result.err)
	}
	workbookXML, _ := readSyntheticWorkbookXML(t, result.artifact.Body) // XLSX 单元格文本位于压缩的内部 XML。
	oldSnapshot := strings.Contains(workbookXML, "Synthetic Snapshot Old Alpha") &&
		strings.Contains(workbookXML, "Synthetic Snapshot Old Beta") &&
		!strings.Contains(workbookXML, "Synthetic Snapshot New Alpha") &&
		!strings.Contains(workbookXML, "Synthetic Snapshot New Beta")
	newSnapshot := strings.Contains(workbookXML, "Synthetic Snapshot New Alpha") &&
		strings.Contains(workbookXML, "Synthetic Snapshot New Beta") &&
		!strings.Contains(workbookXML, "Synthetic Snapshot Old Alpha") &&
		!strings.Contains(workbookXML, "Synthetic Snapshot Old Beta")
	if !oldSnapshot || newSnapshot { // 锁等待前建立的事务快照必须贯穿确认读取和文件生成。
		t.Fatal("export did not remain on one database snapshot")
	}
}

// --- 导出任一失败都不消费确认、不留审计或返回部分文件 ---
func TestExportFailureLeavesConfirmationRetryableWithoutPartialState(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 故障和重试共享同一随机 schema 以观察回滚。
	prepareSyntheticExportIdentities(t, connection)
	clock := newSyntheticExportClock(syntheticExportBaseTime)
	commands, createError := NewCommands(connection, clock.Now)
	if createError != nil {
		t.Fatalf("export commands failed to initialize: %v", createError)
	}
	if _, markerError := connection.Exec(context.Background(), `
		UPDATE students SET phone = 'synthetic-contact-private-marker', next_action = 'synthetic-business-private-marker'
		WHERE id = 'S-syntheticstudent01'`); markerError != nil {
		t.Fatal("synthetic export privacy markers failed to prepare")
	}
	installSyntheticExportAuditFailure(t, connection)
	owner := syntheticExportOwner("A-syntheticowner01")
	issued := issueSyntheticExport(t, commands, owner, "AS-syntheticexportowner01", "students")

	failedArtifact, exportError := commands.RunExport(context.Background(), owner, RunExportInput{
		SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID,
	})
	if !errors.Is(exportError, ErrExportFailed) {
		t.Fatalf("injected export failure did not return the stable failure: %v", exportError)
	}
	requireEmptyExportArtifact(t, failedArtifact)
	if countSyntheticExportAudits(t, connection, syntheticExportRequestID) != 0 {
		t.Fatal("failed export left partial success audit state")
	}
	if _, dropError := connection.Exec(context.Background(), `DROP TRIGGER reject_synthetic_export_audit ON audit_events`); dropError != nil {
		t.Fatal("synthetic export audit failure could not be released")
	}

	artifact, retryError := commands.RunExport(context.Background(), owner, RunExportInput{
		SessionID: "AS-syntheticexportowner01", ExportType: "students", Confirmation: issued.Confirmation, RequestID: syntheticExportRequestID,
	})
	if retryError != nil || len(artifact.Body) == 0 || countSyntheticExportAudits(t, connection, syntheticExportRequestID) != 1 {
		t.Fatalf("rolled-back export confirmation was not retryable: body=%t error=%v", len(artifact.Body) != 0, retryError)
	}
	assertSyntheticExportAuditIsMinimal(t, connection, syntheticExportRequestID, issued.Confirmation)
}

// syntheticExportClock 为确认边界提供线程安全的可控 UTC 事实。
type syntheticExportClock struct {
	mutex sync.RWMutex // mutex 保护并发快照命令读取时间。
	now   time.Time    // now 始终以 UTC 保存当前测试时刻。
}

// --- 建立一个固定 UTC 测试时钟 ---
func newSyntheticExportClock(now time.Time) *syntheticExportClock {
	return &syntheticExportClock{now: now.UTC()} // 输入时区不得改变过期比较。
}

// --- 读取当前可比较时刻 ---
func (clock *syntheticExportClock) Now() time.Time {
	clock.mutex.RLock()
	defer clock.mutex.RUnlock() // 并发导出完成后立即释放时钟读锁。
	return clock.now
}

// --- 将测试时钟推进或重置到明确 UTC 边界 ---
func (clock *syntheticExportClock) Set(now time.Time) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock() // 新边界完整写入后才允许命令读取。
	clock.now = now.UTC()
}

// --- 返回一名当前有效合成老板投影 ---
func syntheticExportOwner(accountID string) auth.Account {
	return auth.Account{ID: accountID, Role: "owner", State: "active", CredentialVersion: 1}
}

// --- 通过公开命令发出一个不输出原始值的合成确认 ---
func issueSyntheticExport(t *testing.T, commands *Commands, actor auth.Account, sessionID string, exportType string) ExportConfirmation {
	t.Helper() // 发出失败归因到调用行为测试。
	issued, issueError := commands.CreateExportConfirmation(context.Background(), actor, ExportConfirmationInput{
		SessionID: sessionID, ExportType: exportType,
	})
	if issueError != nil {
		t.Fatalf("synthetic export confirmation failed: %v", issueError)
	}
	return issued // 原始值只留在当前测试内存。
}

// --- 证明失败路径没有产生任何可下载内容 ---
func requireEmptyExportArtifact(t *testing.T, artifact ExportArtifact) {
	t.Helper() // 失败归因到具体公开行为。
	if artifact.MediaType != "" || len(artifact.Body) != 0 {
		t.Fatal("rejected export returned download content or partial result metadata")
	}
}

// --- 读取工作簿全部文本和首张工作表结构 ---
func readSyntheticWorkbookXML(t *testing.T, body []byte) (string, string) {
	t.Helper() // ZIP 或 XML 结构失败归因到调用的导出行为。
	archive, openError := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if openError != nil {
		t.Fatalf("export is not a valid XLSX container: %v", openError)
	}
	allXML := strings.Builder{} // 中文表头可能位于共享字符串或工作表内联字符串中。
	worksheetXML := ""          // 第一张工作表承载列宽、冻结窗格和筛选范围。
	for _, file := range archive.File {
		opened, fileError := file.Open() // 逐个读取本测试刚生成的内存文件。
		if fileError != nil {
			t.Fatalf("export workbook entry could not be opened: %v", fileError)
		}
		content, readError := io.ReadAll(opened) // 测试工作簿规模固定且只含 synthetic 数据。
		closeError := opened.Close()             // 每个 ZIP 条目读取后立即释放。
		if readError != nil || closeError != nil {
			t.Fatalf("export workbook entry could not be read")
		}
		allXML.Write(content) // 只在内存中聚合结构，用于存在性断言。
		if file.Name == "xl/worksheets/sheet1.xml" {
			worksheetXML = string(content) // 精确锁定首张业务工作表。
		}
	}
	if worksheetXML == "" {
		t.Fatal("export workbook is missing its first worksheet")
	}
	return allXML.String(), worksheetXML // 调用方只检查固定结构标记，不打印正文。
}

// --- 建立两名老板、一名员工和四个独立活动会话 ---
func prepareSyntheticExportIdentities(t *testing.T, connection *pgx.Conn) {
	t.Helper() // 账号或会话夹具错误归因到调用行为。
	if _, ownerError := connection.Exec(context.Background(), `
		INSERT INTO accounts (
			id, username_normalized, username_display, display_name, password_hash,
			role, state, staff_profile_id, credential_version, must_change_password, version
		)
		SELECT 'A-syntheticowner02', 'synthetic-owner-two', 'synthetic-owner-two',
			'Synthetic Owner Two', password_hash, 'owner', 'active', NULL, 1, false, 1
		FROM accounts WHERE id = 'A-syntheticowner01'`); ownerError != nil {
		t.Fatal("synthetic second export owner setup failed")
	}

	createdAt := syntheticExportBaseTime.Add(-time.Minute)
	idleExpiresAt := syntheticExportBaseTime.Add(time.Hour)
	absoluteExpiresAt := syntheticExportBaseTime.Add(24 * time.Hour)
	sessions := []struct {
		id        string // id 是公开命令绑定的会话标识。
		accountID string // accountID 决定会话当前归属。
		familyID  string // familyID 仅满足真实会话结构。
	}{
		{"AS-syntheticexportowner01", "A-syntheticowner01", "RF-syntheticexportfamily01"},
		{"AS-syntheticexportowner03", "A-syntheticowner01", "RF-syntheticexportfamily03"},
		{"AS-syntheticexportowner02", "A-syntheticowner02", "RF-syntheticexportfamily02"},
		{"AS-syntheticexportstaff01", "A-syntheticstaff01", "RF-syntheticexportfamilystaff"},
	}
	for _, session := range sessions {
		digest := sha256.Sum256([]byte(session.id)) // 夹具只保存固定 digest，不需要原始刷新秘密。
		if _, sessionError := connection.Exec(context.Background(), `
			INSERT INTO account_sessions (
				id, account_id, token_family_id, refresh_digest, credential_version,
				user_agent_summary, created_at, last_seen_at, idle_expires_at, absolute_expires_at
			) VALUES ($1, $2, $3, $4, 1, 'Synthetic Export Browser', $5, $5, $6, $7)`,
			session.id, session.accountID, session.familyID, digest[:], createdAt, idleExpiresAt, absoluteExpiresAt); sessionError != nil {
			t.Fatal("synthetic export session setup failed")
		}
	}
}

// --- 打开指向同一随机 schema 的独立 PostgreSQL 会话 ---
func openSyntheticExportPeer(t *testing.T, connection *pgx.Conn, applicationName string) *pgx.Conn {
	t.Helper() // 连接失败归因到并发夹具。
	var schemaName string
	if schemaError := connection.QueryRow(context.Background(), `SELECT current_schema()`).Scan(&schemaName); schemaError != nil {
		t.Fatal("synthetic export schema identity unavailable")
	}
	configuration := connection.Config().Copy() // 复用已验证的 synthetic 地址和内存凭据，不输出它们。
	configuration.RuntimeParams["search_path"] = schemaName
	configuration.RuntimeParams["application_name"] = applicationName
	peer, connectError := pgx.ConnectConfig(context.Background(), configuration)
	if connectError != nil {
		t.Fatal("synthetic export peer connection failed")
	}
	t.Cleanup(func() { _ = peer.Close(context.Background()) }) // 测试完成后只关闭本夹具连接。
	return peer
}

// --- 等待导出 SELECT 已到达可观测快照交叉点 ---
func waitForSyntheticSnapshotBarrier(connection *pgx.Conn, exportBackendPID int32) bool {
	deadline := time.Now().Add(5 * time.Second) // 有界等待避免环境异常被当作产品 RED。
	for time.Now().Before(deadline) {
		var waiting bool
		queryError := connection.QueryRow(context.Background(), `
			SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted)`, exportBackendPID).Scan(&waiting)
		if queryError != nil {
			return false
		}
		if waiting {
			return true // 未授予的事务锁证明导出已进入受控确认读取。
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// --- 仅拒绝导出审计写入，用于验证完整回滚 ---
func installSyntheticExportAuditFailure(t *testing.T, connection *pgx.Conn) {
	t.Helper() // 故障夹具错误归因到回滚行为。
	if _, installError := connection.Exec(context.Background(), `
		CREATE FUNCTION reject_synthetic_export_audit() RETURNS trigger
		LANGUAGE plpgsql AS $failure$
		BEGIN
			IF NEW.object_type = 'export' THEN
				RAISE EXCEPTION 'synthetic export audit rejection';
			END IF;
			RETURN NEW;
		END
		$failure$;
		CREATE TRIGGER reject_synthetic_export_audit
			BEFORE INSERT ON audit_events
			FOR EACH ROW EXECUTE FUNCTION reject_synthetic_export_audit()`); installError != nil {
		t.Fatal("synthetic export audit failure installation failed")
	}
}

// --- 只计数一次请求的导出成功审计 ---
func countSyntheticExportAudits(t *testing.T, connection *pgx.Conn, requestID string) int {
	t.Helper() // 计数失败归因到回滚行为。
	var count int
	if countError := connection.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_events WHERE request_id = $1 AND object_type = 'export'`, requestID).Scan(&count); countError != nil {
		t.Fatal("synthetic export audit count failed")
	}
	return count
}

// --- 证明成功审计不复制导出正文、联系方式或确认秘密 ---
func assertSyntheticExportAuditIsMinimal(t *testing.T, connection *pgx.Conn, requestID string, confirmation string) {
	t.Helper() // 隐私失败归因到成功导出行为。
	rows, queryError := connection.Query(context.Background(), `
		SELECT metadata::text FROM audit_events WHERE request_id = $1 AND object_type = 'export'`, requestID)
	if queryError != nil {
		t.Fatal("synthetic export audit privacy query failed")
	}
	defer rows.Close() // 隐私检查完成或失败时立即释放游标。
	for rows.Next() {
		var metadata string
		if scanError := rows.Scan(&metadata); scanError != nil {
			t.Fatal("synthetic export audit privacy scan failed")
		}
		if strings.Contains(metadata, "synthetic-contact-private-marker") ||
			strings.Contains(metadata, "synthetic-business-private-marker") || strings.Contains(metadata, confirmation) {
			t.Fatal("export audit copied protected content or confirmation material")
		}
	}
	if rowsError := rows.Err(); rowsError != nil {
		t.Fatal("synthetic export audit privacy rows failed")
	}
}
