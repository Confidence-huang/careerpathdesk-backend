/* HTTP 装配合同：学生测评入口必须同时拥有能力解析和测评命令。 */
package assessments

import (
	"errors"
	"testing"
)

func TestHTTPRejectsIncompleteDependencies(t *testing.T) {
	_, httpError := NewHTTP(nil, nil)
	if !errors.Is(httpError, ErrInvalidHTTPDependencies) {
		t.Fatal("incomplete assessment HTTP dependencies were accepted")
	}
}
