-- PostgreSQL schema for CLIProxyAPI

-- ----------------------------
-- Table structure for table cli_oauth
-- ----------------------------
DROP TABLE IF EXISTS "public"."cli_oauth";
CREATE TABLE "public"."cli_oauth" (
  "id" varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "oauth" text COLLATE "pg_catalog"."default" NOT NULL,
  "model_type" int4 NOT NULL,
  "created_at" timestamptz(6),
  "updated_at" timestamptz(6),
  "status" int8,
  "account_id" varchar(250) COLLATE "pg_catalog"."default"
)
;
COMMENT ON COLUMN "public"."cli_oauth"."id" IS 'ID';
COMMENT ON COLUMN "public"."cli_oauth"."oauth" IS 'OAuth 凭证';
COMMENT ON COLUMN "public"."cli_oauth"."model_type" IS '1: Codex 2: Anthropic 3: Qwen';
COMMENT ON COLUMN "public"."cli_oauth"."created_at" IS '创建时间';
COMMENT ON COLUMN "public"."cli_oauth"."updated_at" IS '更新时间';
COMMENT ON COLUMN "public"."cli_oauth"."status" IS '状态 (1:正常 2:禁用)';
COMMENT ON COLUMN "public"."cli_oauth"."account_id" IS '账户ID';
-- ----------------------------
-- Primary Key structure for table cli_oauth
-- ----------------------------
ALTER TABLE "cli_oauth" ADD CONSTRAINT "cli_oauth_pkey" PRIMARY KEY ("id");




-- ----------------------------
-- Table structure for table cli_user
-- ----------------------------
DROP TABLE IF EXISTS "cli_user";
CREATE TABLE "cli_user" (
  "id"         varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "status"     int8 DEFAULT 1,
  "user_id"    varchar(50) COLLATE "pg_catalog"."default",
  "created_at" timestamptz(6),
  "updated_at" timestamptz(6)
);

COMMENT ON TABLE "cli_user" IS 'CLI 用户表';
COMMENT ON COLUMN "cli_user"."id" IS 'ID';
COMMENT ON COLUMN "cli_user"."status" IS '状态 (1:正常 2:禁用 3:删除)';
COMMENT ON COLUMN "cli_user"."user_id" IS '用户ID';
COMMENT ON COLUMN "cli_user"."created_at" IS '创建时间';
COMMENT ON COLUMN "cli_user"."updated_at" IS '更新时间';

-- ----------------------------
-- Indexes structure for table cli_user
-- ----------------------------
CREATE UNIQUE INDEX "idx_user_id" ON "cli_user" USING btree (
  "user_id" COLLATE "pg_catalog"."default" "pg_catalog"."text_ops" ASC NULLS LAST
);

-- ----------------------------
-- Uniques structure for table cli_user
-- ----------------------------
ALTER TABLE "cli_user" ADD CONSTRAINT "idx_cli_user_user_id" UNIQUE ("user_id");

-- ----------------------------
-- Primary Key structure for table cli_user
-- ----------------------------
ALTER TABLE "cli_user" ADD CONSTRAINT "cli_user_pkey" PRIMARY KEY ("id");




-- ----------------------------
-- Table structure for table cli_user_oauth
-- ----------------------------
DROP TABLE IF EXISTS "cli_user_oauth";
CREATE TABLE "cli_user_oauth" (
  "id"          varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "cli_user_id" varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "cli_oauth_id" varchar(50) COLLATE "pg_catalog"."default" NOT NULL
);

COMMENT ON TABLE "cli_user_oauth" IS 'CLI 用户凭证关联表';
COMMENT ON COLUMN "cli_user_oauth"."id" IS 'ID';
COMMENT ON COLUMN "cli_user_oauth"."cli_user_id" IS 'CLI 用户ID';
COMMENT ON COLUMN "cli_user_oauth"."cli_oauth_id" IS 'CLI 认证ID';

-- ----------------------------
-- Primary Key structure for table cli_user_oauth
-- ----------------------------
ALTER TABLE "cli_user_oauth" ADD CONSTRAINT "cli_user_oauth_pkey" PRIMARY KEY ("id");
