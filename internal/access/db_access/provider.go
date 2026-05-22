package dbaccess

import (
	"context"
	"net/http"
	"strings"

	"gitee.com/chunanyong/zorm"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

const providerType = "db-user-oauth"

// Register 娉ㄥ唽鍩轰簬鏁版嵁搴?cli_user_oauth 琛ㄧ殑璁よ瘉 provider
func Register() {
	sdkaccess.RegisterProvider(providerType, &provider{})
}

// Unregister 娉ㄩ攢 DB 璁よ瘉 provider
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

	// 鏌ヨ cli_user_oauth 琛ㄩ獙璇?cli_user_id 鏄惁瀛樺湪
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

// extractAPIKey 浠庤姹備腑鎻愬彇 API key锛屾敮鎸佸绉?header 鍜?query 鍙傛暟
func extractAPIKey(r *http.Request) string {
	// Authorization: Bearer <key>
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			if key := strings.TrimSpace(parts[1]); key != "" {
				return key
			}
		}
		// 鐩存帴鏄?key 娌℃湁 Bearer 鍓嶇紑
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
