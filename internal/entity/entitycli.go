package entity

import (
	"time"

	"gitee.com/chunanyong/zorm"
)

// CLIOauth 对应数据库 cli_oauth 表
type CLIOauth struct {
	zorm.EntityStruct
	ID        string     `column:"id" json:"id"`
	Oauth     string     `column:"oauth" json:"oauth"`
	ModelType int        `column:"model_type" json:"modelType"` // 1: Codex 2: Anthropic 3: Qwen
	CreatedAt *time.Time `column:"created_at" json:"createdAt"`
	UpdatedAt *time.Time `column:"updated_at" json:"updatedAt"`
	Status    int        `column:"status" json:"status"` // 1:正常 2:禁用
}

func (e *CLIOauth) GetTableName() string {
	return "cli_oauth"
}

func (e *CLIOauth) GetPKColumnName() string {
	return "id"
}

// CLIUser 对应数据库 cli_user 表
type CLIUser struct {
	zorm.EntityStruct
	ID        string     `column:"id" json:"id"`
	Status    int        `column:"status" json:"status"`  // 1:正常 2:禁用 3:删除
	UserID    string     `column:"user_id" json:"userId"` // 用户ID
	CreatedAt *time.Time `column:"created_at" json:"createdAt"`
	UpdatedAt *time.Time `column:"updated_at" json:"updatedAt"`
}

func (e *CLIUser) GetTableName() string {
	return "cli_user"
}

func (e *CLIUser) GetPKColumnName() string {
	return "id"
}

// CLIUserOauth 对应数据库 cli_user_oauth 表
type CLIUserOauth struct {
	zorm.EntityStruct
	ID         string `column:"id" json:"id"`
	CliUserId  string `column:"cli_user_id" json:"cliUserId"`
	CliOauthId string `column:"cli_oauth_id" json:"cliOauthId"`
}

func (e *CLIUserOauth) GetTableName() string {
	return "cli_user_oauth"
}

func (e *CLIUserOauth) GetPKColumnName() string {
	return "id"
}
