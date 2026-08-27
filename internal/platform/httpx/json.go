/*
严格 JSON 边界：把业务 HTTP 入口共同需要的媒体类型、正文上限和单对象规则收拢一次。
调用方仍负责自己的字段合同；本工具不读取身份、不映射业务错误，也不记录正文。
*/
package httpx

import (
	"encoding/json" // 使用标准流式解码器并拒绝未声明字段。
	"errors"        // 以 EOF 证明请求中只有一个 JSON 值。
	"io"            // 识别 JSON 对象后的正常正文终点。
	"mime"          // 接受 application/json 及合法 charset 参数。
	"net/http"      // 在读取时施加硬字节上限。

	"github.com/gin-gonic/gin" // 消费当前请求正文和响应写入边界。
)

// OptionalField 区分 PATCH 字段缺失、明确 null 和具体新值。
type OptionalField[Value any] struct {
	Value Value // Value 保存请求明确提交的新值，指针类型可表达 null。
	Set   bool  // Set 只在 JSON 中实际出现该字段时为 true。
}

// --- 记录 PATCH 字段明确出现并解码其值 ---
func (field *OptionalField[Value]) UnmarshalJSON(data []byte) error {
	field.Set = true
	return json.Unmarshal(data, &field.Value) // 具体类型继续使用标准 JSON 值规则。
}

// --- 解码一个有界、白名单且唯一的 JSON 对象 ---
func DecodeSingleJSON(context *gin.Context, target any, maximumBytes int64) error {
	if target == nil || maximumBytes < 1 { // 缺少目标或上限时失败关闭。
		return errors.New("invalid JSON decoder configuration")
	}
	mediaType, _, mediaTypeError := mime.ParseMediaType(context.GetHeader("Content-Type"))
	if mediaTypeError != nil || mediaType != "application/json" {
		return errors.New("invalid JSON media type")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(context.Writer, context.Request.Body, maximumBytes))
	decoder.DisallowUnknownFields()
	if decodeError := decoder.Decode(target); decodeError != nil {
		return decodeError
	}
	if trailingError := decoder.Decode(&struct{}{}); !errors.Is(trailingError, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}
