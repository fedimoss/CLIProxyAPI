package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"

	"gitee.com/chunanyong/zorm"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/clioauth"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// UserOAuthPinMiddleware 为当前 CLI 用户固定一个 OAuth 凭据，并注入到请求上下文中。
func UserOAuthPinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, exists := c.Get("apiKey")
		if !exists {
			c.Next()
			return
		}
		cliUserID, ok := raw.(string)
		if !ok || strings.TrimSpace(cliUserID) == "" {
			c.Next()
			return
		}

		entry := log.NewEntry(log.StandardLogger())
		if reqID := logging.GetRequestID(c.Request.Context()); reqID != "" {
			entry = entry.WithField("request_id", reqID)
		}

		// 从请求体中的 model 字段推断 provider，以便优先匹配对应的 model_type。
		rawModel, providers := extractProvidersFromRequest(c)
		desiredModelTypes := modelTypesForProviders(providers)

		candidates, err := listUserOauthCandidates(c.Request.Context(), cliUserID)
		if err != nil {
			entry.WithError(err).Warnf("user oauth pin: query candidates failed (cli_user_id=%s)", util.HideAPIKey(cliUserID))
			c.Next()
			return
		}
		if len(candidates) == 0 {
			if log.IsLevelEnabled(log.DebugLevel) {
				entry.Debugf("user oauth pin: no oauth candidates (cli_user_id=%s model=%q providers=%v)", util.HideAPIKey(cliUserID), rawModel, providers)
			}
			c.Next()
			return
		}

		filtered := filterCandidatesByModelTypes(candidates, desiredModelTypes)
		selected := pickCandidate(filtered)
		selectedSource := "filtered"
		if selected == nil {
			// 回退：保持旧有行为（选取任意关联的 OAuth），避免破坏非标准路由。
			selected = pickCandidate(candidates)
			selectedSource = "fallback_any"
			if log.IsLevelEnabled(log.DebugLevel) {
				entry.Debugf("user oauth pin: no provider-matching oauth (cli_user_id=%s model=%q providers=%v desired_model_types=%v candidates=%d)", util.HideAPIKey(cliUserID), rawModel, providers, desiredModelTypes, len(candidates))
			}
		}
		if selected == nil || strings.TrimSpace(selected.CliOauthId) == "" {
			c.Next()
			return
		}

		if log.IsLevelEnabled(log.DebugLevel) {
			entry.Debugf("user oauth pin: selected cli_oauth_id=%s (source=%s cli_user_id=%s model=%q providers=%v model_type=%d candidates=%d)", selected.CliOauthId, selectedSource, util.HideAPIKey(cliUserID), rawModel, providers, selected.ModelType, len(candidates))
		}

		// 将固定的 auth ID 注入到请求上下文中
		ctx := handlers.WithPinnedAuthID(c.Request.Context(), selected.CliOauthId)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

type userOauthCandidate struct {
	CliOauthId string `column:"cli_oauth_id" json:"cliOauthId"`
	ModelType  int    `column:"model_type" json:"modelType"`
}

// extractProvidersFromRequest 从请求体中解析 model 字段，返回原始模型名和对应的 provider 列表。
func extractProvidersFromRequest(c *gin.Context) (rawModel string, providers []string) {
	if c == nil || c.Request == nil {
		return "", nil
	}
	switch c.Request.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return "", nil
	}
	if c.Request.Body == nil {
		return "", nil
	}

	// 读取请求体并在读取后恢复，以便下游处理器使用。
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.Request.Body = io.NopCloser(bytes.NewReader(nil))
		return "", nil
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	rawModel = strings.TrimSpace(gjson.GetBytes(body, "model").String())
	if rawModel == "" {
		return "", nil
	}

	// 与处理器端的模型规范化保持一致（auto 模型解析及 thinking 后缀保留）。
	resolvedModelName := rawModel
	initialSuffix := thinking.ParseSuffix(rawModel)
	if initialSuffix.ModelName == "auto" {
		resolvedBase := util.ResolveAutoModel(initialSuffix.ModelName)
		if initialSuffix.HasSuffix {
			resolvedModelName = fmt.Sprintf("%s(%s)", resolvedBase, initialSuffix.RawSuffix)
		} else {
			resolvedModelName = resolvedBase
		}
	} else {
		resolvedModelName = util.ResolveAutoModel(rawModel)
	}

	parsed := thinking.ParseSuffix(resolvedModelName)
	baseModel := strings.TrimSpace(parsed.ModelName)
	providers = util.GetProviderName(baseModel)
	if len(providers) == 0 && baseModel != resolvedModelName {
		providers = util.GetProviderName(resolvedModelName)
	}
	return rawModel, providers
}

// modelTypesForProviders 将 provider 名称列表转换为对应的 modelType 去重列表。
func modelTypesForProviders(providers []string) []int {
	if len(providers) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(providers))
	out := make([]int, 0, len(providers))
	for _, provider := range providers {
		modelType := clioauth.ProviderToModelType(provider)
		if modelType == 0 {
			continue
		}
		if _, ok := seen[modelType]; ok {
			continue
		}
		seen[modelType] = struct{}{}
		out = append(out, modelType)
	}
	return out
}

// listUserOauthCandidates 查询指定 CLI 用户关联的所有可用 OAuth 候选项。
func listUserOauthCandidates(ctx context.Context, cliUserID string) ([]*userOauthCandidate, error) {
	cliUserID = strings.TrimSpace(cliUserID)
	if cliUserID == "" {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// 关联 cli_user_oauth 和 cli_oauth 表，确保引用的 OAuth 凭据存在且已启用。
	finder := zorm.NewSelectFinder("cli_user_oauth uo join cli_oauth o on o.id = uo.cli_oauth_id", "uo.cli_oauth_id, o.model_type")
	finder.Append("where uo.cli_user_id=?", cliUserID)
	finder.Append("and (o.status is null or o.status=1)")

	var rows []*userOauthCandidate
	if err := zorm.Query(ctx, finder, &rows, nil); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	// 过滤掉旧版文件名格式的 ID（防御性检查）。
	out := make([]*userOauthCandidate, 0, len(rows))
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row == nil {
			continue
		}
		id := strings.TrimSpace(row.CliOauthId)
		if id == "" {
			continue
		}
		if strings.Contains(id, ".json") || strings.Contains(id, "/") || strings.Contains(id, "\\") {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		row.CliOauthId = id
		out = append(out, row)
	}
	return out, nil
}

// filterCandidatesByModelTypes 按 modelType 过滤候选项，仅保留匹配期望类型的候选。
func filterCandidatesByModelTypes(candidates []*userOauthCandidate, desired []int) []*userOauthCandidate {
	if len(candidates) == 0 || len(desired) == 0 {
		return candidates
	}
	desiredSet := make(map[int]struct{}, len(desired))
	for _, mt := range desired {
		desiredSet[mt] = struct{}{}
	}
	out := make([]*userOauthCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if _, ok := desiredSet[candidate.ModelType]; !ok {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

// pickCandidate 从候选项列表中随机选取一个。
func pickCandidate(candidates []*userOauthCandidate) *userOauthCandidate {
	if len(candidates) == 0 {
		return nil
	}
	return candidates[rand.IntN(len(candidates))]
}

// chainMiddleware 将多个 gin 中间件组合为一个处理器。
func chainMiddleware(middlewares ...gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, mw := range middlewares {
			mw(c)
			if c.IsAborted() {
				return
			}
		}
	}
}
