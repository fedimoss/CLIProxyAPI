package entity

import (
	"time"

	"gitee.com/chunanyong/zorm"
)

// CLIOauth maps to the cli_oauth table.
type CLIOauth struct {
	zorm.EntityStruct
	ID        string     `column:"id" json:"id"`
	Oauth     string     `column:"oauth" json:"oauth"`
	ModelType int        `column:"model_type" json:"modelType"`
	CreatedAt *time.Time `column:"created_at" json:"createdAt"`
	UpdatedAt *time.Time `column:"updated_at" json:"updatedAt"`
	Status    int        `column:"status" json:"status"`
	// ErrorReason 保存原始上游错误文本，便于后续排查。
	ErrorReason string `column:"error_reason" json:"errorReason"`
	AccountID   string `column:"account_id" json:"accountId"`
}

func (e *CLIOauth) GetTableName() string {
	return "cli_oauth"
}

func (e *CLIOauth) GetPKColumnName() string {
	return "id"
}

// CLIUser maps to the cli_user table.
type CLIUser struct {
	zorm.EntityStruct
	ID        string     `column:"id" json:"id"`
	Status    int        `column:"status" json:"status"`
	UserID    string     `column:"user_id" json:"userId"`
	CreatedAt *time.Time `column:"created_at" json:"createdAt"`
	UpdatedAt *time.Time `column:"updated_at" json:"updatedAt"`
}

func (e *CLIUser) GetTableName() string {
	return "cli_user"
}

func (e *CLIUser) GetPKColumnName() string {
	return "id"
}

// CLIUserOauth maps to the cli_user_oauth table.
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
