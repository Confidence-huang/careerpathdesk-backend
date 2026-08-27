/*
一致导出：短期确认只保存 SHA-256，并在 Repeatable Read 事务中重新验证账号、会话和绑定。
XLSX 生成、确认消费和最小成功审计共享一个提交边界；任何失败只反馈固定错误和空文件。
*/
package operations

import (
	"context"         // 驱动确认签发、快照查询和原子提交。
	"crypto/rand"     // 生成不可预测的一次确认原始值。
	"crypto/sha256"   // 数据库只保存和匹配固定长度 confirmation digest。
	"encoding/base64" // 将随机字节编码为浏览器安全的不透明文本。
	"encoding/json"   // 只编码导出类型与行数两个最小审计事实。
	"fmt"             // 生成明确的工作表单元格和筛选范围。
	"time"            // 比较会话与确认的精确 UTC 边界。
	"unicode/utf8"    // 按公开字符数验证请求 ID。

	"github.com/jackc/pgx/v5"     // 提供行锁、Repeatable Read 和稳定无行分类。
	"github.com/xuri/excelize/v2" // 生成 WPS/Excel 可读取且能保存列宽的 OOXML 工作簿。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth" // 接受已认证账号投影并再次动态授权。
)

const exportConfirmationBytes = 32                                                          // 256 位随机原始值不依赖账号、时间或数据库序号。
const exportMediaType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" // 浏览器据此保留 XLSX 二进制类型。

type exportColumn struct {
	header      string  // header 是用户在 WPS 中看到的中文列名。
	width       float64 // width 保存适合该业务内容的阅读宽度。
	sourceIndex int     // sourceIndex 指向固定 SQL 结果中的唯一值。
}

type exportWorksheetDefinition struct {
	name          string         // name 是最多 31 字符的中文工作表名称。
	freezeColumns int            // freezeColumns 让横向滚动时保留关键身份列。
	columns       []exportColumn // columns 冻结当前工作表的顺序、标题和宽度。
}

type exportWorkbookDefinition struct {
	valueCount int                         // valueCount 必须与固定 SQL SELECT 列数完全一致。
	statement  string                      // statement 只来自下方固定注册表，不接受调用方 SQL。
	worksheets []exportWorksheetDefinition // worksheets 把同一快照组织为一个或多个易读表格。
}

// --- 为当前老板、当前会话和一种导出签发短期一次确认 ---
func (commands *Commands) CreateExportConfirmation(ctx context.Context, actor auth.Account, input ExportConfirmationInput) (ExportConfirmation, error) {
	if actor.Role != "owner" { // 角色门禁先于会话和类型形状，阻止员工探测确认合同。
		return ExportConfirmation{}, ErrForbidden
	}
	if !validSessionID(input.SessionID) || !supportedExportType(input.ExportType) {
		return ExportConfirmation{}, ErrInvalidInput
	}
	raw, randomError := newExportConfirmation()
	if randomError != nil {
		return ExportConfirmation{}, ErrExportFailed
	}
	digest := sha256.Sum256([]byte(raw))
	now := commands.now().UTC()
	expiresAt := now.Add(exportConfirmationLifetime)
	transaction, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return ExportConfirmation{}, ErrExportFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, actorError := requireCurrentActor(ctx, transaction, actor)
	if actorError != nil || current.role != "owner" {
		return ExportConfirmation{}, actorErrorOrForbidden(actorError)
	}
	if sessionError := requireCurrentExportSession(ctx, transaction, actor, input.SessionID, now); sessionError != nil {
		return ExportConfirmation{}, sessionError
	}
	if _, insertError := transaction.Exec(ctx, `
		INSERT INTO export_confirmations (
			confirmation_digest, account_id, session_id, export_type, expires_at
		) VALUES ($1, $2, $3, $4, $5)`, digest[:], current.id, input.SessionID, input.ExportType, expiresAt,
	); insertError != nil {
		return ExportConfirmation{}, ErrExportFailed
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return ExportConfirmation{}, ErrExportFailed
	}
	return ExportConfirmation{Confirmation: raw, ExpiresAt: expiresAt}, nil // 原始确认只在提交后反馈一次。
}

// --- 在一个一致快照中生成、消费并审计导出 ---
func (commands *Commands) RunExport(ctx context.Context, actor auth.Account, input RunExportInput) (ExportArtifact, error) {
	if actor.Role != "owner" { // 越权请求不解析会话、类型、确认或请求 ID。
		return ExportArtifact{}, ErrForbidden
	}
	if !validRunExportInput(input) {
		return ExportArtifact{}, ErrInvalidInput
	}
	digest := sha256.Sum256([]byte(input.Confirmation))
	auditID, auditIdentityError := commands.newIdentity("AU")
	if auditIdentityError != nil {
		return ExportArtifact{}, ErrExportFailed
	}
	exportID, exportIdentityError := commands.newIdentity("EX")
	if exportIdentityError != nil {
		return ExportArtifact{}, ErrExportFailed
	}
	now := commands.now().UTC()
	transaction, beginError := commands.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if beginError != nil {
		return ExportArtifact{}, ErrExportFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, actorError := requireCurrentActor(ctx, transaction, actor)
	if actorError != nil || current.role != "owner" {
		return ExportArtifact{}, normalizeExportAuthorizationError(actorError)
	}
	if sessionError := requireCurrentExportSession(ctx, transaction, actor, input.SessionID, now); sessionError != nil {
		return ExportArtifact{}, normalizeExportAuthorizationError(sessionError)
	}
	if confirmationError := lockExportConfirmation(ctx, transaction, digest, current.id, input, now); confirmationError != nil {
		return ExportArtifact{}, confirmationError
	}
	body, recordCount, renderError := renderExportWorkbook(ctx, transaction, input.ExportType)
	if renderError != nil {
		return ExportArtifact{}, ErrExportFailed
	}
	consumeTag, consumeError := transaction.Exec(ctx, `
		UPDATE export_confirmations SET used_at = $2
		WHERE confirmation_digest = $1 AND used_at IS NULL`, digest[:], now)
	if consumeError != nil || consumeTag.RowsAffected() != 1 {
		return ExportArtifact{}, ErrExportFailed
	}
	metadata, metadataError := json.Marshal(map[string]any{"export_type": input.ExportType, "record_count": recordCount})
	if metadataError != nil {
		return ExportArtifact{}, ErrExportFailed
	}
	if _, auditError := transaction.Exec(ctx, `
		INSERT INTO audit_events (
			id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at
		) VALUES ($1, 'account', $2, 'export.completed', 'export', $3, 'success', $4, $5::jsonb, $6)`,
		auditID, current.id, exportID, input.RequestID, metadata, now,
	); auditError != nil {
		return ExportArtifact{}, ErrExportFailed
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return ExportArtifact{}, ErrExportFailed
	}
	return ExportArtifact{MediaType: exportMediaType, Body: body}, nil // 提交前的正文绝不越过公开边界。
}

func newExportConfirmation() (string, error) {
	randomBytes := make([]byte, exportConfirmationBytes)
	if _, readError := rand.Read(randomBytes); readError != nil {
		return "", readError
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func supportedExportType(exportType string) bool {
	return exportType == "students" || exportType == "follow-ups" || exportType == "assessments"
}

func validSessionID(sessionID string) bool {
	return len(sessionID) >= 15 && len(sessionID) <= 83 && len(sessionID) >= 3 && sessionID[:3] == "AS-"
}

func validRunExportInput(input RunExportInput) bool {
	return validSessionID(input.SessionID) && supportedExportType(input.ExportType) &&
		len(input.Confirmation) >= 1 && len(input.Confirmation) <= 256 && utf8.ValidString(input.RequestID) &&
		utf8.RuneCountInString(input.RequestID) >= 8 && utf8.RuneCountInString(input.RequestID) <= 100
}

// --- 动态验证访问投影仍对应当前活动会话和凭据版本 ---
func requireCurrentExportSession(ctx context.Context, transaction pgx.Tx, actor auth.Account, sessionID string, now time.Time) error {
	var sessionCredentialVersion, accountCredentialVersion int64
	var revokedAt *time.Time
	var idleExpiresAt, absoluteExpiresAt time.Time
	queryError := transaction.QueryRow(ctx, `
		SELECT session.credential_version, account.credential_version,
			session.revoked_at, session.idle_expires_at, session.absolute_expires_at
		FROM account_sessions AS session
		JOIN accounts AS account ON account.id = session.account_id
		WHERE session.id = $1 AND session.account_id = $2
		FOR SHARE OF session`, sessionID, actor.ID,
	).Scan(&sessionCredentialVersion, &accountCredentialVersion, &revokedAt, &idleExpiresAt, &absoluteExpiresAt)
	if queryError != nil {
		if queryError == pgx.ErrNoRows {
			return ErrForbidden
		}
		return ErrOperationFailed
	}
	if actor.CredentialVersion < 1 || actor.CredentialVersion != accountCredentialVersion ||
		sessionCredentialVersion != accountCredentialVersion || revokedAt != nil ||
		!now.Before(idleExpiresAt) || !now.Before(absoluteExpiresAt) {
		return ErrForbidden
	}
	return nil
}

// --- 锁定且统一隐藏未知、误绑、过期和已消费确认 ---
func lockExportConfirmation(ctx context.Context, transaction pgx.Tx, digest [sha256.Size]byte, accountID string, input RunExportInput, now time.Time) error {
	var lockedDigest []byte
	queryError := transaction.QueryRow(ctx, `
		SELECT confirmation_digest
		FROM export_confirmations
		WHERE confirmation_digest = $1 AND account_id = $2 AND session_id = $3
			AND export_type = $4 AND used_at IS NULL AND expires_at > $5
		FOR UPDATE`, digest[:], accountID, input.SessionID, input.ExportType, now,
	).Scan(&lockedDigest)
	if queryError != nil {
		if queryError == pgx.ErrNoRows {
			return ErrExportConfirmationUnavailable
		}
		return ErrExportFailed
	}
	return nil
}

func normalizeExportAuthorizationError(authorizeError error) error {
	if authorizeError == ErrOperationFailed {
		return ErrExportFailed
	}
	return ErrForbidden
}

// --- 由固定注册表选择一种中文工作簿，不让调用方输入成为标识符 ---
func renderExportWorkbook(ctx context.Context, transaction pgx.Tx, exportType string) ([]byte, int, error) {
	definition, found := exportWorkbookDefinitions()[exportType]
	if !found {
		return nil, 0, ErrExportFailed
	}
	rows, queryError := transaction.Query(ctx, definition.statement)
	if queryError != nil {
		return nil, 0, ErrExportFailed
	}
	defer rows.Close()
	workbook := excelize.NewFile()          // 工作簿只存在于当前命令内存，事务提交前不会反馈给浏览器。
	defer func() { _ = workbook.Close() }() // 成功或失败都释放 Excelize 的临时内存资源。
	headerStyle, bodyStyle, styleError := createExportStyles(workbook)
	if styleError != nil {
		return nil, 0, ErrExportFailed
	}
	if prepareError := prepareExportWorksheets(workbook, definition, headerStyle); prepareError != nil {
		return nil, 0, ErrExportFailed
	}
	recordCount := 0
	for rows.Next() {
		values := make([]string, definition.valueCount) // 每一行严格匹配注册表声明的 SELECT 列数。
		destinations := make([]any, len(values))
		for index := range values {
			destinations[index] = &values[index] // pgx 将每个公开表格值扫描为文本。
		}
		if scanError := rows.Scan(destinations...); scanError != nil {
			return nil, 0, ErrExportFailed
		}
		recordCount++ // 第一条数据写入工作表第 2 行，首行固定留给中文表头。
		if writeError := writeExportWorkbookRow(workbook, definition, values, recordCount+1); writeError != nil {
			return nil, 0, ErrExportFailed
		}
	}
	if rows.Err() != nil {
		return nil, 0, ErrExportFailed
	}
	if finalizeError := finalizeExportWorksheets(workbook, definition, recordCount, bodyStyle); finalizeError != nil {
		return nil, 0, ErrExportFailed
	}
	buffer, writeError := workbook.WriteToBuffer() // 完整 OOXML 在内存中封装为 ZIP 后才允许进入提交阶段。
	if writeError != nil {
		return nil, 0, ErrExportFailed
	}
	return append([]byte(nil), buffer.Bytes()...), recordCount, nil // 返回独立副本，工作簿关闭后正文仍有效。
}

// --- 建立中文表头和正文的统一阅读样式 ---
func createExportStyles(workbook *excelize.File) (int, int, error) {
	border := []excelize.Border{
		{Type: "left", Color: "D7E0EE", Style: 1},   // 浅色边框区分相邻业务列。
		{Type: "right", Color: "D7E0EE", Style: 1},  // 横向浏览时保留单元格边界。
		{Type: "top", Color: "D7E0EE", Style: 1},    // 表头和正文使用同一网格节奏。
		{Type: "bottom", Color: "D7E0EE", Style: 1}, // 长文本换行后仍能辨认所属记录。
	}
	headerStyle, headerError := workbook.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF", Family: "微软雅黑", Size: 11},         // 深色表头使用白色中文字体。
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"2458B8"}},         // 与后台主色保持一致。
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true}, // 短中文表头居中并允许换行。
		Border:    border,
	})
	if headerError != nil {
		return 0, 0, headerError
	}
	bodyStyle, bodyError := workbook.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Color: "172033", Family: "微软雅黑", Size: 10}, // 正文使用稳定深色和中文字体。
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},      // 经历和下一步等长文本在固定宽度内换行。
		Border:    border,
	})
	if bodyError != nil {
		return 0, 0, bodyError
	}
	return headerStyle, bodyStyle, nil // 两个样式 ID 只属于当前工作簿。
}

// --- 创建工作表、中文表头、列宽和冻结窗格 ---
func prepareExportWorksheets(workbook *excelize.File, definition exportWorkbookDefinition, headerStyle int) error {
	for worksheetIndex, worksheet := range definition.worksheets {
		if len(worksheet.columns) == 0 {
			return ErrExportFailed // 空工作表代表注册表不完整，必须失败关闭。
		}
		if worksheetIndex == 0 {
			if renameError := workbook.SetSheetName("Sheet1", worksheet.name); renameError != nil {
				return renameError // 首张默认表改为中文业务名称。
			}
		} else if _, createError := workbook.NewSheet(worksheet.name); createError != nil {
			return createError // 额外技术信息表与业务表保存在同一文件。
		}
		headers := make([]any, len(worksheet.columns)) // SetSheetRow 接收一行显式值。
		for columnIndex, column := range worksheet.columns {
			headers[columnIndex] = column.header // 用户只看到中文表头，不暴露数据库字段名。
			columnName, nameError := excelize.ColumnNumberToName(columnIndex + 1)
			if nameError != nil {
				return nameError
			}
			if widthError := workbook.SetColWidth(worksheet.name, columnName, columnName, column.width); widthError != nil {
				return widthError // 每列按内容类型保存 WPS 可读取的明确宽度。
			}
		}
		lastColumn, nameError := excelize.ColumnNumberToName(len(worksheet.columns))
		if nameError != nil {
			return nameError
		}
		if rowError := workbook.SetSheetRow(worksheet.name, "A1", &headers); rowError != nil {
			return rowError // 中文表头写入固定第一行。
		}
		if styleError := workbook.SetCellStyle(worksheet.name, "A1", lastColumn+"1", headerStyle); styleError != nil {
			return styleError // 表头样式覆盖当前表的完整列范围。
		}
		if heightError := workbook.SetRowHeight(worksheet.name, 1, 30); heightError != nil {
			return heightError // 30 点高度让两行中文表头仍完整可见。
		}
		panes := &excelize.Panes{
			Freeze: true, Split: false, XSplit: worksheet.freezeColumns, YSplit: 1,
			TopLeftCell: fmt.Sprintf("%s2", frozenTopLeftColumn(worksheet.freezeColumns)), ActivePane: frozenActivePane(worksheet.freezeColumns),
		}
		if panesError := workbook.SetPanes(worksheet.name, panes); panesError != nil {
			return panesError // 冻结首行和关键身份列，横向滚动时不丢失上下文。
		}
	}
	workbook.SetActiveSheet(0) // 文件打开时首先呈现业务工作表，而不是系统信息。
	return nil
}

// --- 把查询的一行投影到每张工作表 ---
func writeExportWorkbookRow(workbook *excelize.File, definition exportWorkbookDefinition, values []string, rowNumber int) error {
	for _, worksheet := range definition.worksheets {
		row := make([]any, len(worksheet.columns)) // 每张表只选取其获准业务列。
		for columnIndex, column := range worksheet.columns {
			if column.sourceIndex < 0 || column.sourceIndex >= len(values) {
				return ErrExportFailed // 注册表索引漂移时拒绝产生错列文件。
			}
			row[columnIndex] = values[column.sourceIndex] // 字符串写入不会被解释为公式。
		}
		if rowError := workbook.SetSheetRow(worksheet.name, fmt.Sprintf("A%d", rowNumber), &row); rowError != nil {
			return rowError // 同一数据库记录在各工作表使用同一行号。
		}
	}
	return nil
}

// --- 完成正文样式和可筛选范围 ---
func finalizeExportWorksheets(workbook *excelize.File, definition exportWorkbookDefinition, recordCount int, bodyStyle int) error {
	lastRow := recordCount + 1 // 即使零记录也保留可筛选的中文表头行。
	for _, worksheet := range definition.worksheets {
		lastColumn, nameError := excelize.ColumnNumberToName(len(worksheet.columns))
		if nameError != nil {
			return nameError
		}
		if recordCount > 0 {
			if styleError := workbook.SetCellStyle(worksheet.name, "A2", fmt.Sprintf("%s%d", lastColumn, lastRow), bodyStyle); styleError != nil {
				return styleError // 正文统一启用边框、顶端对齐和自动换行。
			}
		}
		if filterError := workbook.AutoFilter(worksheet.name, fmt.Sprintf("A1:%s%d", lastColumn, lastRow), []excelize.AutoFilterOptions{}); filterError != nil {
			return filterError // WPS 打开后可直接按地区、负责人和协作老师等字段筛选。
		}
	}
	return nil
}

// --- 计算冻结窗格右下区域的首列 ---
func frozenTopLeftColumn(freezeColumns int) string {
	column, convertError := excelize.ColumnNumberToName(freezeColumns + 1)
	if convertError != nil {
		return "A" // 注册表常量异常时由 SetPanes 继续失败关闭，不传播空坐标。
	}
	return column
}

// --- 选择冻结窗格的活动区域 ---
func frozenActivePane(freezeColumns int) string {
	if freezeColumns > 0 {
		return "bottomRight" // 同时冻结首行和左侧身份列时数据区域位于右下。
	}
	return "bottomLeft" // 只冻结首行时数据区域位于下方。
}

// exportWorkbookDefinitions 是全部获准导出列、中文名称和稳定顺序的唯一注册表。
func exportWorkbookDefinitions() map[string]exportWorkbookDefinition {
	return map[string]exportWorkbookDefinition{
		"students": {
			valueCount: 28,
			worksheets: []exportWorksheetDefinition{
				{name: "学生资料", freezeColumns: 2, columns: []exportColumn{
					{header: "学生编号", width: 22, sourceIndex: 0}, {header: "姓名", width: 16, sourceIndex: 1},
					{header: "电话", width: 16, sourceIndex: 2}, {header: "邮箱", width: 26, sourceIndex: 3},
					{header: "微信", width: 18, sourceIndex: 4}, {header: "学校", width: 20, sourceIndex: 5},
					{header: "专业", width: 18, sourceIndex: 6}, {header: "年级", width: 12, sourceIndex: 7},
					{header: "现居地", width: 16, sourceIndex: 8}, {header: "目标城市", width: 14, sourceIndex: 9},
					{header: "目标岗位", width: 20, sourceIndex: 10}, {header: "期望薪资", width: 14, sourceIndex: 11},
					{header: "求职意向", width: 24, sourceIndex: 12}, {header: "项目经历", width: 36, sourceIndex: 13},
					{header: "实习经历", width: 36, sourceIndex: 14}, {header: "技能", width: 30, sourceIndex: 15},
					{header: "证书", width: 26, sourceIndex: 16}, {header: "主负责人", width: 18, sourceIndex: 17},
					{header: "协作老师", width: 26, sourceIndex: 18}, {header: "下一步行动", width: 36, sourceIndex: 19},
					{header: "下次跟进时间", width: 22, sourceIndex: 20}, {header: "资料来源", width: 16, sourceIndex: 21},
				}},
				{name: "系统信息", freezeColumns: 1, columns: []exportColumn{
					{header: "学生编号", width: 22, sourceIndex: 0}, {header: "负责人档案编号", width: 22, sourceIndex: 22},
					{header: "数据版本", width: 12, sourceIndex: 23}, {header: "创建来源", width: 20, sourceIndex: 24},
					{header: "更新来源", width: 20, sourceIndex: 25}, {header: "创建时间", width: 24, sourceIndex: 26},
					{header: "更新时间", width: 24, sourceIndex: 27},
				}},
			},
			statement: `SELECT student.id, student.name, COALESCE(student.phone, ''), COALESCE(student.email, ''), COALESCE(student.wechat, ''),
				COALESCE(student.school, ''), COALESCE(student.major, ''), COALESCE(student.grade, ''), COALESCE(student.current_location, ''),
				COALESCE(student.target_city, ''), COALESCE(student.target_position, ''), COALESCE(student.expected_salary, ''),
				COALESCE(student.job_intention, ''), COALESCE(student.project_experience, ''), COALESCE(student.internship_experience, ''),
				COALESCE(student.skills, ''), COALESCE(student.certificates, ''), COALESCE(current_owner.display_name, legacy_owner.display_name, '暂未分配'),
				COALESCE(collaborators.display_names, ''), COALESCE(student.next_action, ''),
				COALESCE(student.next_follow_up_at::text, ''), CASE student.source_kind
					WHEN 'staff' THEN '员工录入' WHEN 'invitation' THEN '学生邀请填写' ELSE '历史数据迁移' END,
				COALESCE(current_owner.id, student.owner_staff_id, ''), student.version::text,
				COALESCE(created_account.display_name, CASE student.source_kind WHEN 'invitation' THEN '学生邀请' WHEN 'migration' THEN '历史迁移' ELSE student.created_by END),
				COALESCE(updated_account.display_name, CASE student.source_kind WHEN 'invitation' THEN '学生邀请' WHEN 'migration' THEN '历史迁移' ELSE student.updated_by END),
				student.created_at::text, student.updated_at::text
				FROM students AS student
				LEFT JOIN staff_profiles AS legacy_owner ON legacy_owner.id = student.owner_staff_id
				LEFT JOIN LATERAL (
					SELECT staff.id, staff.display_name FROM student_staff_assignments AS assignment
					JOIN staff_profiles AS staff ON staff.id = assignment.staff_profile_id
					WHERE assignment.student_id = student.id AND assignment.assignment_role = 'primary' AND assignment.ended_at IS NULL
					ORDER BY assignment.started_at DESC, assignment.id DESC LIMIT 1
				) AS current_owner ON true
				LEFT JOIN LATERAL (
					SELECT string_agg(staff.display_name, '、' ORDER BY assignment.started_at, assignment.id) AS display_names
					FROM student_staff_assignments AS assignment
					JOIN staff_profiles AS staff ON staff.id = assignment.staff_profile_id
					WHERE assignment.student_id = student.id AND assignment.assignment_role = 'collaborator' AND assignment.ended_at IS NULL
				) AS collaborators ON true
				LEFT JOIN accounts AS created_account ON created_account.id = student.created_by
				LEFT JOIN accounts AS updated_account ON updated_account.id = student.updated_by
				ORDER BY student.id`,
		},
		"follow-ups": {
			valueCount: 18,
			worksheets: []exportWorksheetDefinition{{name: "跟进记录", freezeColumns: 2, columns: []exportColumn{
				{header: "跟进编号", width: 22, sourceIndex: 0}, {header: "学生编号", width: 22, sourceIndex: 1},
				{header: "联系时间", width: 22, sourceIndex: 2}, {header: "联系渠道", width: 14, sourceIndex: 3},
				{header: "有效联系", width: 12, sourceIndex: 4}, {header: "需要回复", width: 12, sourceIndex: 5},
				{header: "回复事项编号", width: 22, sourceIndex: 6}, {header: "学生回复时间", width: 22, sourceIndex: 7},
				{header: "确认逾期", width: 12, sourceIndex: 8}, {header: "本次跟进内容", width: 48, sourceIndex: 9},
				{header: "下一步行动", width: 36, sourceIndex: 10}, {header: "下一位跟进老师", width: 20, sourceIndex: 11},
				{header: "下次跟进时间", width: 22, sourceIndex: 12}, {header: "数据版本", width: 12, sourceIndex: 13},
				{header: "创建人", width: 20, sourceIndex: 14}, {header: "更新人", width: 20, sourceIndex: 15},
				{header: "创建时间", width: 24, sourceIndex: 16}, {header: "更新时间", width: 24, sourceIndex: 17},
			}},
			},
			statement: `SELECT follow_up.id, follow_up.student_id, follow_up.contacted_at::text, follow_up.channel,
				CASE WHEN follow_up.valid_contact THEN '是' ELSE '否' END,
				CASE WHEN follow_up.reply_required THEN '是' ELSE '否' END, COALESCE(follow_up.reply_thread_id, ''),
				COALESCE(follow_up.student_replied_at::text, ''), CASE WHEN follow_up.overdue_occurrence THEN '是' ELSE '否' END,
				COALESCE(follow_up.content, ''), COALESCE(follow_up.next_action, ''), COALESCE(next_staff.display_name, ''),
				COALESCE(follow_up.next_follow_up_at::text, ''), follow_up.version::text,
				COALESCE(created_account.display_name, follow_up.created_by), COALESCE(updated_account.display_name, follow_up.updated_by),
				follow_up.created_at::text, follow_up.updated_at::text
				FROM follow_up_records AS follow_up
				LEFT JOIN accounts AS created_account ON created_account.id = follow_up.created_by
				LEFT JOIN accounts AS updated_account ON updated_account.id = follow_up.updated_by
				LEFT JOIN staff_profiles AS next_staff ON next_staff.id = follow_up.next_staff_id
				ORDER BY follow_up.id`,
		},
		"assessments": {
			valueCount: 11,
			worksheets: []exportWorksheetDefinition{{name: "测评结果", freezeColumns: 2, columns: []exportColumn{
				{header: "测评编号", width: 22, sourceIndex: 0}, {header: "学生编号", width: 22, sourceIndex: 1},
				{header: "问卷版本", width: 18, sourceIndex: 2}, {header: "问卷答案（系统数据）", width: 42, sourceIndex: 3},
				{header: "系统评分", width: 42, sourceIndex: 4}, {header: "内部建议", width: 42, sourceIndex: 5},
				{header: "来源邀请编号", width: 22, sourceIndex: 6}, {header: "数据版本", width: 12, sourceIndex: 7},
				{header: "提交时间", width: 24, sourceIndex: 8}, {header: "创建时间", width: 24, sourceIndex: 9},
				{header: "更新时间", width: 24, sourceIndex: 10},
			}},
			},
			statement: `SELECT id, student_id, questionnaire_version, answers::text, server_score::text,
				internal_recommendation::text, source_invitation_id, version::text, submitted_at::text,
				created_at::text, updated_at::text FROM assessments ORDER BY id`,
		},
	}
}
