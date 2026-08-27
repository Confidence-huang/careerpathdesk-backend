/*
结构化安全日志测试：公开入口只能编码固定元数据字段，不能接收任意业务正文。
*/
package safelog

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWriteEmitsOnlyAllowlistedMetadata(t *testing.T) {
	var output bytes.Buffer
	entry := Entry{
		At:        time.Date(2026, 8, 5, 4, 0, 0, 0, time.UTC),
		Level:     "info",
		Event:     "http.completed",
		Outcome:   "success",
		RequestID: "R-syntheticrequest",
		Count:     1,
	}
	if writeError := Write(&output, entry); writeError != nil {
		t.Fatalf("safe log write failed: %v", writeError)
	}
	line := output.String()
	for _, required := range []string{"\"event\":\"http.completed\"", "\"requestId\":\"R-syntheticrequest\"", "\"count\":1"} {
		if !strings.Contains(line, required) {
			t.Fatalf("safe log missing %s: %s", required, line)
		}
	}
	for _, forbidden := range []string{"password", "token", "phone", "email", "body"} {
		if strings.Contains(strings.ToLower(line), forbidden) {
			t.Fatalf("safe log contains forbidden field %q", forbidden)
		}
	}
}
