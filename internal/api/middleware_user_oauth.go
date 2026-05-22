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
	"github.com/router-for-me/CLIProxyAPI/v7/internal/clioauth"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// UserOAuthPinMiddleware 涓哄綋鍓?CLI 鐢ㄦ埛鍥哄畾涓€涓?OAuth 鍑嵁锛屽苟娉ㄥ叆鍒拌姹備笂涓嬫枃涓€?
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

		// 浠庤姹備綋涓殑 model 瀛楁鎺ㄦ柇 provider锛屼互渚夸紭鍏堝尮閰嶅搴旂殑 model_type銆?
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
			// 鍥為€€锛氫繚鎸佹棫鏈夎涓猴紙閫夊彇浠绘剰鍏宠仈鐨?OAuth锛夛紝閬垮厤鐮村潖闈炴爣鍑嗚矾鐢便€?
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

		// 灏嗗浐瀹氱殑 auth ID 娉ㄥ叆鍒拌姹備笂涓嬫枃涓?
		ctx := handlers.WithPinnedAuthID(c.Request.Context(), selected.CliOauthId)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

type userOauthCandidate struct {
	CliOauthId string `column:"cli_oauth_id" json:"cliOauthId"`
	ModelType  int    `column:"model_type" json:"modelType"`
}

// extractProvidersFromRequest 浠庤姹備綋涓В鏋?model 瀛楁锛岃繑鍥炲師濮嬫ā鍨嬪悕鍜屽搴旂殑 provider 鍒楄〃銆?
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

	// 璇诲彇璇锋眰浣撳苟鍦ㄨ鍙栧悗鎭㈠锛屼互渚夸笅娓稿鐞嗗櫒浣跨敤銆?
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

	// 涓庡鐞嗗櫒绔殑妯″瀷瑙勮寖鍖栦繚鎸佷竴鑷达紙auto 妯″瀷瑙ｆ瀽鍙?thinking 鍚庣紑淇濈暀锛夈€?
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

// modelTypesForProviders 灏?provider 鍚嶇О鍒楄〃杞崲涓哄搴旂殑 modelType 鍘婚噸鍒楄〃銆?
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

// listUserOauthCandidates 鏌ヨ鎸囧畾 CLI 鐢ㄦ埛鍏宠仈鐨勬墍鏈夊彲鐢?OAuth 鍊欓€夐」銆?
func listUserOauthCandidates(ctx context.Context, cliUserID string) ([]*userOauthCandidate, error) {
	cliUserID = strings.TrimSpace(cliUserID)
	if cliUserID == "" {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// 鍏宠仈 cli_user_oauth 鍜?cli_oauth 琛紝纭繚寮曠敤鐨?OAuth 鍑嵁瀛樺湪涓斿凡鍚敤銆?
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

	// 杩囨护鎺夋棫鐗堟枃浠跺悕鏍煎紡鐨?ID锛堥槻寰℃€ф鏌ワ級銆?
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

// filterCandidatesByModelTypes 鎸?modelType 杩囨护鍊欓€夐」锛屼粎淇濈暀鍖归厤鏈熸湜绫诲瀷鐨勫€欓€夈€?
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

// pickCandidate 浠庡€欓€夐」鍒楄〃涓殢鏈洪€夊彇涓€涓€?
func pickCandidate(candidates []*userOauthCandidate) *userOauthCandidate {
	if len(candidates) == 0 {
		return nil
	}
	return candidates[rand.IntN(len(candidates))]
}

// chainMiddleware 灏嗗涓?gin 涓棿浠剁粍鍚堜负涓€涓鐞嗗櫒銆?
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
