/* UTC 系统时钟：为命令层提供单一可替换时间来源。 */
package clock

import "time" // 读取系统时间并立即规范为 UTC。

// System 是生产进程的无状态 UTC 时钟。
type System struct{}

// Now 反馈当前 UTC 时间，不携带宿主机本地时区。
func (System) Now() time.Time {
	return time.Now().UTC()
}
