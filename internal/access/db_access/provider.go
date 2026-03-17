package dbaccess

import (
	"context"
	"net/http"
	"strings"

	"gitee.com/chunanyong/zorm"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
)

const providerType = "db-user-oauth"

// Register 注册基于数据库 cli_user_oauth 表的认证 provider
func Register() {
	sdkaccess.RegisterProvider(providerType, &provider{})
}

// Unregister 注销 DB 认证 provider
func Unregister() {
	sdkaccess.UnregisterProvider(providerType)
}

type provider struct{}

func (p *provider) Identifier() string {
	return providerType
}

func (p *provider) Authenticate(ctx context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	apiKey := extractAPIKey(r)
	if apiKey == "" {
		return nil, sdkaccess.NewNoCredentialsError()
	}

	// 查询 cli_user_oauth 表验证 cli_user_id 是否存在
	finder := zorm.NewSelectFinder("cli_user_oauth", "count(*)")
	finder.Append("WHERE cli_user_id=?", apiKey)

	var count int
	has, err := zorm.QueryRow(ctx, finder, &count)
	if err != nil || !has || count == 0 {
		return nil, sdkaccess.NewInvalidCredentialError()
	}

	return &sdkaccess.Result{
		Provider:  providerType,
		Principal: apiKey,
		Metadata:  map[string]string{"source": "db-user-oauth"},
	}, nil
}

// extractAPIKey 从请求中提取 API key，支持多种 header 和 query 参数
func extractAPIKey(r *http.Request) string {
	// Authorization: Bearer <key>
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			if key := strings.TrimSpace(parts[1]); key != "" {
				return key
			}
		}
		// 直接是 key 没有 Bearer 前缀
		if key := strings.TrimSpace(auth); key != "" {
			return key
		}
	}
	// X-Api-Key (Anthropic style)
	if key := strings.TrimSpace(r.Header.Get("X-Api-Key")); key != "" {
		return key
	}
	// X-Goog-Api-Key (Google style)
	if key := strings.TrimSpace(r.Header.Get("X-Goog-Api-Key")); key != "" {
		return key
	}
	// Query parameters
	if r.URL != nil {
		if key := strings.TrimSpace(r.URL.Query().Get("key")); key != "" {
			return key
		}
		if key := strings.TrimSpace(r.URL.Query().Get("auth_token")); key != "" {
			return key
		}
	}
	return ""
}
