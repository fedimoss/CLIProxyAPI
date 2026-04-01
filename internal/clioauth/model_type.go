package clioauth

import "strings"

// 这组常量定义了 cli_oauth 表里使用的 model_type 编号。
const (
	ModelTypeUnknown     = 0
	ModelTypeCodex       = 1
	ModelTypeAnthropic   = 2
	ModelTypeQwen        = 3
	ModelTypeGemini      = 4
	ModelTypeAntigravity = 5
	ModelTypeKimi        = 6
	ModelTypeIFlow       = 7
)

// ProviderToModelType 把 provider 名称映射成数据库里的 model_type 编号。
func ProviderToModelType(provider string) int {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex", "openai":
		return ModelTypeCodex
	case "claude", "anthropic":
		return ModelTypeAnthropic
	case "qwen":
		return ModelTypeQwen
	case "gemini":
		return ModelTypeGemini
	case "antigravity":
		return ModelTypeAntigravity
	case "kimi":
		return ModelTypeKimi
	case "iflow":
		return ModelTypeIFlow
	default:
		return ModelTypeUnknown
	}
}

// ModelTypeToProvider 把数据库里的 model_type 编号还原成 provider 名称。
func ModelTypeToProvider(modelType int) string {
	switch modelType {
	case ModelTypeCodex:
		return "codex"
	case ModelTypeAnthropic:
		return "claude"
	case ModelTypeQwen:
		return "qwen"
	case ModelTypeGemini:
		return "gemini"
	case ModelTypeAntigravity:
		return "antigravity"
	case ModelTypeKimi:
		return "kimi"
	case ModelTypeIFlow:
		return "iflow"
	default:
		return "unknown"
	}
}
