/* HTTP 装配合同：运营入口需要命令和账号/会话联合身份能力。 */
package operations

import (
	"errors"
	"testing"
)

func TestHTTPRejectsIncompleteDependencies(t *testing.T) {
	_, httpError := NewHTTP(nil, nil)
	if !errors.Is(httpError, ErrInvalidHTTPDependencies) {
		t.Fatal("incomplete operations HTTP dependencies were accepted")
	}
}
