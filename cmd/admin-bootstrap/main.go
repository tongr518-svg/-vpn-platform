package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	emailFlag := flag.String("email", "", "已注册的管理员账号邮箱")
	flag.Parse()

	email := strings.ToLower(strings.TrimSpace(*emailFlag))
	if email == "" {
		log.Fatal("必须通过 -email 指定已注册账号邮箱")
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL 环境变量不能为空")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatal("连接数据库失败：", err)
	}
	defer db.Close()

	if err := db.Ping(ctx); err != nil {
		log.Fatal("数据库不可用：", err)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		log.Fatal("开启事务失败：", err)
	}
	defer tx.Rollback(ctx)

	// Serialize bootstrap attempts so only one process can pass the first-admin check.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock($1)`,
		int64(74192368051235),
	); err != nil {
		log.Fatal("获取管理员初始化锁失败：", err)
	}

	var adminExists bool
	err = tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')`,
	).Scan(&adminExists)
	if err != nil {
		log.Fatal("检查管理员账号失败：", err)
	}
	if adminExists {
		log.Fatal("数据库中已存在管理员；为避免意外提权，本命令不会修改账号")
	}

	var userID int64
	var status string
	err = tx.QueryRow(ctx,
		`SELECT id, status
		 FROM users
		 WHERE lower(email) = $1
		 FOR UPDATE`,
		email,
	).Scan(&userID, &status)
	if err == pgx.ErrNoRows {
		log.Fatal("找不到该邮箱对应的账号，请先完成邀请注册")
	}
	if err != nil {
		log.Fatal("查询账号失败：", err)
	}
	if status != "active" {
		log.Fatal("该账号不是 active 状态，不能提升为管理员")
	}

	if _, err := tx.Exec(ctx,
		`UPDATE users
		 SET role = 'admin',
		     token_version = token_version + 1
		 WHERE id = $1`,
		userID,
	); err != nil {
		log.Fatal("提升管理员角色失败：", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit_logs
		 (actor_user_id, action, target_type, target_id)
		 VALUES ($1, 'bootstrap_admin', 'user', $2)`,
		userID,
		fmt.Sprint(userID),
	); err != nil {
		log.Fatal("写入审计日志失败：", err)
	}

	if err := tx.Commit(ctx); err != nil {
		log.Fatal("提交事务失败：", err)
	}

	fmt.Printf("已将 %s 提升为首位管理员。\n", email)
}
