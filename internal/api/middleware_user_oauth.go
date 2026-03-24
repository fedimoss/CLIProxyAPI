package api

import (
	"context"
	"math/rand"
	"strings"

	"gitee.com/chunanyong/zorm"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/entity"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/api/handlers"
)

// UserOAuthPinMiddleware 根据 API key（cli_user_id）查询关联的 cli_oauth_id，
// 随机选一个注入到 context 的 pinned auth ID，使 conductor 使用对应的 OAuth 凭证。
func UserOAuthPinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, exists := c.Get("apiKey")
		if !exists {
			c.Next()
			return
		}
		cliUserID, ok := raw.(string)
		if !ok || cliUserID == "" {
			c.Next()
			return
		}

		// 查询 cli_user_oauth 表获取该用户关联的所有 cli_oauth_id
		finder := zorm.NewSelectFinder((&entity.CLIUserOauth{}).GetTableName())
		finder.Append("WHERE cli_user_id=?", cliUserID)

		var userOauths []entity.CLIUserOauth
		if err := zorm.Query(context.Background(), finder, &userOauths, nil); err != nil || len(userOauths) == 0 {
			c.Next()
			return
		}

		// 随机选一个 cli_oauth_id，过滤掉文件名格式的旧数据
		var validOauths []entity.CLIUserOauth
		for _, uo := range userOauths {
			// 跳过文件名格式的旧数据（包含 .json 或 /）
			if strings.Contains(uo.CliOauthId, ".json") || strings.Contains(uo.CliOauthId, "/") || strings.Contains(uo.CliOauthId, "\\") {
				continue
			}
			validOauths = append(validOauths, uo)
		}

		if len(validOauths) == 0 {
			// 没有有效的 oauth ID，不设置 pinned auth
			c.Next()
			return
		}

		selected := validOauths[rand.Intn(len(validOauths))]

		// 注入 pinned auth ID 到 request context
		ctx := handlers.WithPinnedAuthID(c.Request.Context(), selected.CliOauthId)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// chainMiddleware 将多个 gin 中间件合并为单个 HandlerFunc。
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
