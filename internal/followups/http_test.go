/* HTTP 装配合同：缺少跟进、状态或当前账号能力时不得注册半可用路由。 */
package followups

import (
	"errors"
	"testing"
)

func TestHTTPRejectsIncompleteDependencies(t *testing.T) {
	_, httpError := NewHTTP(nil, nil)
	if !errors.Is(httpError, ErrInvalidHTTPDependencies) {
		t.Fatal("incomplete follow-up HTTP dependencies were accepted")
	}
}
