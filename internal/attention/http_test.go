/* HTTP 装配合同：关注入口必须同时拥有领域命令和当前账号能力。 */
package attention

import (
	"errors"
	"testing"
)

func TestHTTPRejectsIncompleteDependencies(t *testing.T) {
	_, httpError := NewHTTP(nil, nil)
	if !errors.Is(httpError, ErrInvalidHTTPDependencies) {
		t.Fatal("incomplete attention HTTP dependencies were accepted")
	}
}
