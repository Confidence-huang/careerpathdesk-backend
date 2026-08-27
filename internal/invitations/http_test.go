/* HTTP 装配合同：后台邀请入口必须拒绝缺失命令、身份或公开来源。 */
package invitations

import (
	"errors"
	"testing"
)

func TestHTTPRejectsIncompleteDependencies(t *testing.T) {
	_, httpError := NewHTTP(nil, nil, "")
	if !errors.Is(httpError, ErrInvalidHTTPDependencies) {
		t.Fatal("incomplete invitation HTTP dependencies were accepted")
	}
}
