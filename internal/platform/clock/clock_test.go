/* UTC 时钟测试：所有持久化和会话计算只接收 UTC 时间事实。 */
package clock

import (
	"testing"
	"time"
)

func TestSystemNowReturnsUTC(t *testing.T) {
	now := System{}.Now()
	if now.Location() != time.UTC {
		t.Fatalf("expected UTC location, got %s", now.Location())
	}
}
