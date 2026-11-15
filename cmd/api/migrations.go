package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func applyMigrations(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("创建迁移记录表失败: %w", err)
	}
	if _, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migration_checksums (
			version TEXT PRIMARY KEY
				REFERENCES schema_migrations(version) ON DELETE CASCADE,
			checksum TEXT NOT NULL,
			recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("创建迁移校验和表失败: %w", err)
	}

	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("读取迁移目录失败: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		version := strings.TrimSuffix(entry.Name(), ".sql")
		sqlBytes, err := migrationFiles.ReadFile(path.Join("migrations", entry.Name()))
		if err != nil {
			return fmt.Errorf("读取迁移 %s 失败: %w", version, err)
		}
		sum := sha256.Sum256(sqlBytes)
		checksum := hex.EncodeToString(sum[:])

		tx, err := db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("启动迁移 %s 事务失败: %w", version, err)
		}

		// Serialize migration runs when multiple API instances start together.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(74192368051234)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("获取迁移锁失败: %w", err)
		}

		var alreadyApplied bool
		err = tx.QueryRow(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM schema_migrations WHERE version = $1
			)`,
			version,
		).Scan(&alreadyApplied)
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("检查迁移 %s 状态失败: %w", version, err)
		}

		if alreadyApplied {
			var storedChecksum string
			err := tx.QueryRow(ctx,
				`SELECT checksum
				 FROM schema_migration_checksums
				 WHERE version = $1`,
				version,
			).Scan(&storedChecksum)

			switch {
			case err == pgx.ErrNoRows:
				// Baseline migrations applied before checksums were introduced.
				if _, err := tx.Exec(ctx,
					`INSERT INTO schema_migration_checksums (version, checksum)
					 VALUES ($1, $2)`,
					version, checksum,
				); err != nil {
					_ = tx.Rollback(ctx)
					return fmt.Errorf("记录迁移 %s 校验和失败: %w", version, err)
				}

			case err != nil:
				_ = tx.Rollback(ctx)
				return fmt.Errorf("读取迁移 %s 校验和失败: %w", version, err)

			case storedChecksum != checksum:
				_ = tx.Rollback(ctx)
				return fmt.Errorf("迁移 %s 的校验和不匹配；已应用的迁移文件不得修改", version)
			}

			if err := tx.Commit(ctx); err != nil {
				return fmt.Errorf("结束迁移 %s 检查事务失败: %w", version, err)
			}
			continue
		}

		// Use PostgreSQL's simple protocol to execute the migration's multiple statements.
		if _, err := tx.Exec(ctx, string(sqlBytes), pgx.QueryExecModeSimpleProtocol); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("执行迁移 %s 失败: %w", version, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`,
			version,
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("记录迁移 %s 失败: %w", version, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migration_checksums (version, checksum)
			 VALUES ($1, $2)`,
			version, checksum,
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("记录迁移 %s 校验和失败: %w", version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("提交迁移 %s 失败: %w", version, err)
		}
	}
	return nil
}
