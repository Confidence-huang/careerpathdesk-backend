/*
Migration 文件加载器：把只读文件系统中的编号 SQL 转换为严格有序的 Migration。
加载器拒绝未知文件名、空目录和读取错误，不推测版本，也不接触数据库。
调用示例：migrations, loadError := migrate.Load(os.DirFS("database/migrations"))。
*/
package migrate

import (
	"errors"  // 暴露空 migration 集合的稳定失败分类。
	"fmt"     // 为无效文件增加安全文件名上下文。
	"io/fs"   // 接收磁盘或嵌入式只读 migration 文件系统。
	"regexp"  // 强制文件名采用四位版本和业务名称。
	"sort"    // 在任何文件系统实现下保持确定性版本顺序。
	"strconv" // 将四位文件版本转换为账本整数。
)

var ErrNoMigrations = errors.New("no migration files found")                               // 标识 schema 来源为空，禁止假装已是最新。
var migrationFileName = regexp.MustCompile(`^([0-9]{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`) // 限定可审查的 migration 文件身份。

// --- 加载并排序全部编号 SQL ---
func Load(migrationFiles fs.FS) ([]Migration, error) {
	entries, readError := fs.ReadDir(migrationFiles, ".") // 只读取调用方明确提供的 migration 根目录。
	if readError != nil {                                 // 目录缺失或不可读时不提供空 schema 回退。
		return nil, readError
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() }) // 固定跨文件系统顺序。

	migrations := make([]Migration, 0, len(entries)) // 预留显式文件数量，保持版本顺序可见。
	for _, entry := range entries {                  // 每个目录项都必须是合法 migration 文件。
		migration, loadError := loadOne(migrationFiles, entry)
		if loadError != nil { // 任一未知文件或内容读取失败都拒绝整组加载。
			return nil, loadError
		}
		migrations = append(migrations, migration) // 将已验证文件加入有序 schema 指令。
	}
	if len(migrations) == 0 { // 空目录不能代表数据库已经完成迁移。
		return nil, ErrNoMigrations
	}
	if orderError := validateOrder(migrations); orderError != nil { // 文件名也必须形成严格递增版本。
		return nil, orderError
	}

	return migrations, nil // 反馈可直接交给 Apply 的完整有序列表。
}

// --- 加载一个编号 SQL 文件 ---
func loadOne(migrationFiles fs.FS, entry fs.DirEntry) (Migration, error) {
	fileName := entry.Name()                                  // 读取人工可审查且不含业务数据的文件身份。
	matches := migrationFileName.FindStringSubmatch(fileName) // 拆出四位版本和稳定名称。
	if entry.IsDir() || matches == nil {                      // 子目录和未知命名都不允许被静默忽略。
		return Migration{}, fmt.Errorf("invalid migration file %q", fileName)
	}

	version, parseError := strconv.ParseInt(matches[1], 10, 64) // 将固定四位版本转换为账本值。
	if parseError != nil {                                      // 理论上正则已保证数字，仍对未知解析失败关闭。
		return Migration{}, fmt.Errorf("parse migration file %q: %w", fileName, parseError)
	}
	sqlBytes, readError := fs.ReadFile(migrationFiles, fileName) // 读取完整 SQL 字节作为 checksum 和执行来源。
	if readError != nil {                                        // 无法读取时不返回部分 migration 集合。
		return Migration{}, fmt.Errorf("read migration file %q: %w", fileName, readError)
	}

	return Migration{Version: version, Name: matches[2], SQL: string(sqlBytes)}, nil // 反馈一个完整不可猜测的 schema 指令。
}
