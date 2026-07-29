package config

const (
	DefaultPanelGitHubRepository                     = "https://github.com/router-for-me/Cli-Proxy-API-Management-Center"
	DefaultPprofAddr                                 = "127.0.0.1:8316"
	DefaultAuthDir                                   = "~/.cli-proxy-api"
	DefaultOAuthHealthProbeIntervalMinutes           = 15
	DefaultOAuthHealthProbeMinRemainingWeeklyPercent = 90
	// DefaultCLIUserID 用于在未显式传 cli_user_id 时，给数据库模式下的 OAuth 记录做默认关联。
	DefaultCLIUserID = "u_10001"
)

// DefaultOAuthHealthProbeMaxWorkers 是 OAuth 健康探测的最大并发 worker 数默认值。
// 当配置文件中未指定 max-workers 或指定值 ≤ 0 时使用此默认值。
const DefaultOAuthHealthProbeMaxWorkers = 16
