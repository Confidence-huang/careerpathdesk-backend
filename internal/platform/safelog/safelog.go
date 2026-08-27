/*
结构化安全日志：只接收固定运行元数据，不提供任意 map 或 error 正文入口。
业务正文、联系方式、凭据、Token、Cookie 和 SQL 无法通过 Entry 字段进入普通日志。
*/
package safelog

import (
	"encoding/json" // 输出单行机器可读 JSON，不拼接不可信字符串。
	"io"            // 接受进程日志 writer 或测试缓冲区。
	"time"          // 使用调用方注入的 UTC 发生时间。
)

// Entry 是普通运行日志唯一允许的数据包。
type Entry struct {
	At        time.Time `json:"at"`                  // At 是 UTC 运行时间事实。
	Level     string    `json:"level"`               // Level 由调用点使用固定级别。
	Event     string    `json:"event"`               // Event 是固定运行事件码。
	Outcome   string    `json:"outcome"`             // Outcome 是固定结果类别。
	RequestID string    `json:"requestId,omitempty"` // RequestID 关联一次 HTTP 请求。
	ObjectID  string    `json:"objectId,omitempty"`  // ObjectID 只在最小审计允许时使用不透明 ID。
	Count     int       `json:"count,omitempty"`     // Count 反馈聚合数量，不反馈业务行。
}

// --- 编码一个固定字段日志事件 ---
func Write(writer io.Writer, entry Entry) error {
	entry.At = entry.At.UTC()                    // 即使调用方传入本地时间也统一输出 UTC。
	return json.NewEncoder(writer).Encode(entry) // JSON 编码负责转义，单次调用产生一行反馈。
}
