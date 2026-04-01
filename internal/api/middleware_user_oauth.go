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

// UserOAuthPinMiddleware 鏍规嵁 API key锛坈li_user_id锛夋煡璇㈠叧鑱旂殑 cli_oauth_id锛?// 闅忔満閫変竴涓敞鍏ュ埌 context 鐨?pinned auth ID锛屼娇 conductor 浣跨敤瀵瑰簲鐨?OAuth 鍑瘉銆?
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

		// Infer provider(s) from the request payload model so we can prefer the matching model_type.
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
			// Fallback: keep legacy behavior (pick any associated oauth) so we don't break non-standard routes.
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

		// Inject pinned auth ID into request context
		ctx := handlers.WithPinnedAuthID(c.Request.Context(), selected.CliOauthId)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

type userOauthCandidate struct {
	CliOauthId string `column:"cli_oauth_id" json:"cliOauthId"`
	ModelType  int    `column:"model_type" json:"modelType"`
}

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

	// Read and restore body for downstream handlers.
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

	// Mirror handler-side model normalization (auto + thinking suffix preservation).
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

func listUserOauthCandidates(ctx context.Context, cliUserID string) ([]*userOauthCandidate, error) {
	cliUserID = strings.TrimSpace(cliUserID)
	if cliUserID == "" {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// Join cli_user_oauth -> cli_oauth to ensure the referenced auth exists and is enabled.
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

	// Filter out legacy file-name-format IDs (defensive).
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

func pickCandidate(candidates []*userOauthCandidate) *userOauthCandidate {
	if len(candidates) == 0 {
		return nil
	}
	return candidates[rand.IntN(len(candidates))]
}

// chainMiddleware 灏嗗涓?gin 涓棿浠跺悎骞朵负鍗曚釜 HandlerFunc銆?
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
