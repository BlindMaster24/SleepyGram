// This is the source code of AyuGram for Desktop.
#include "ayu/data/archive_partition.h"

#include "ayu/libs/sqlite/sqlite3.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <string_view>

namespace Ayu {
namespace {

constexpr auto kAccountTables = std::array{
	"DeletedDialog",
	"DeletedMessage",
	"EditedMessage",
	"SpyMessageContentsRead",
	"SpyMessageRead",
};

constexpr auto kUnassignedTables = std::array{
	"RegexFilter",
	"RegexFilterGlobalExclusion",
};

struct Finalize final {
	void operator()(sqlite3_stmt *statement) const {
		sqlite3_finalize(statement);
	}
};

using Statement = std::unique_ptr<sqlite3_stmt, Finalize>;

Statement Prepare(sqlite3 &database, const std::string &query) {
	auto statement = (sqlite3_stmt*)nullptr;
	const auto result = sqlite3_prepare_v2(
		&database, query.c_str(), -1, &statement, nullptr);
	auto prepared = Statement(statement);
	return (result == SQLITE_OK) ? std::move(prepared) : Statement();
}

bool Execute(sqlite3 &database, const char *sql) {
	return sqlite3_exec(&database, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

class Transaction final {
public:
	explicit Transaction(sqlite3 &database)
	: _database(database)
	, _active(Execute(_database, "BEGIN")) {
	}

	~Transaction() {
		if (_active) {
			Execute(_database, "ROLLBACK");
		}
	}

	[[nodiscard]] bool active() const {
		return _active;
	}

	[[nodiscard]] bool commit() {
		if (!_active || !Execute(_database, "COMMIT")) {
			return false;
		}
		_active = false;
		return true;
	}

private:
	sqlite3 &_database;
	bool _active = false;
};

bool KnownTable(std::string_view table) {
	const auto contains = [&](const auto &names) {
		return std::ranges::find(names, table) != names.end();
	};
	return contains(kAccountTables)
		|| contains(kUnassignedTables)
		|| table == "SchemaVersion"
		|| table == "sqlite_sequence";
}

ArchivePartitionResult CheckSource(
		sqlite3 &legacy,
		const std::set<int64_t> &owners) {
	using Result = ArchivePartitionResult;
	auto tables = Prepare(legacy,
		"SELECT name, type FROM sqlite_schema WHERE type != 'index'");
	if (!tables) {
		return Result::InvalidSource;
	}
	auto present = std::set<std::string>();
	auto result = int();
	while ((result = sqlite3_step(tables.get())) == SQLITE_ROW) {
		const auto name = sqlite3_column_text(tables.get(), 0);
		const auto type = sqlite3_column_text(tables.get(), 1);
		if (!name || !type || std::strcmp(reinterpret_cast<const char*>(type), "table")
			|| !KnownTable(reinterpret_cast<const char*>(name))) {
			return Result::InvalidSource;
		}
		present.emplace(reinterpret_cast<const char*>(name));
	}
	if (result != SQLITE_DONE) {
		return Result::ReadWriteFailed;
	}
	for (const auto table : kUnassignedTables) {
		if (!present.contains(table)) {
			continue;
		}
		auto rows = Prepare(legacy, std::string("SELECT 1 FROM ") + table + " LIMIT 1");
		if (!rows) {
			return Result::InvalidSource;
		}
		const auto status = sqlite3_step(rows.get());
		if (status != SQLITE_DONE) {
			return status == SQLITE_ROW ? Result::UnassignedFilters : Result::ReadWriteFailed;
		}
	}
	for (const auto table : kAccountTables) {
		auto rows = Prepare(legacy, std::string("SELECT DISTINCT userId FROM ") + table);
		if (!rows) {
			return Result::InvalidSource;
		}
		auto status = int();
		while ((status = sqlite3_step(rows.get())) == SQLITE_ROW) {
			if (sqlite3_column_type(rows.get(), 0) != SQLITE_INTEGER
				|| !owners.contains(sqlite3_column_int64(rows.get(), 0))) {
				return Result::UnassignedRows;
			}
		}
		if (status != SQLITE_DONE) {
			return Result::ReadWriteFailed;
		}
	}
	return Result::Success;
}

bool CipherEnabled(sqlite3 &database) {
	auto cipher = Prepare(database, "PRAGMA cipher_status");
	return cipher && sqlite3_step(cipher.get()) == SQLITE_ROW
		&& sqlite3_column_int(cipher.get(), 0) == 1;
}

bool MatchingColumns(sqlite3_stmt &source, sqlite3_stmt &destination) {
	const auto count = sqlite3_column_count(&source);
	if (count != sqlite3_column_count(&destination) || !count) {
		return false;
	}
	for (auto column = 0; column != count; ++column) {
		const auto name = sqlite3_column_name(&source, column);
		const auto other = sqlite3_column_name(&destination, column);
		if (!name || !other || std::strcmp(name, other)) {
			return false;
		}
	}
	return true;
}

bool SameValue(sqlite3_stmt &source, sqlite3_stmt &destination, int column) {
	const auto type = sqlite3_column_type(&source, column);
	if (type != sqlite3_column_type(&destination, column)) {
		return false;
	}
	switch (type) {
	case SQLITE_NULL: return true;
	case SQLITE_INTEGER:
		return sqlite3_column_int64(&source, column)
			== sqlite3_column_int64(&destination, column);
	case SQLITE_FLOAT:
		return sqlite3_column_double(&source, column)
			== sqlite3_column_double(&destination, column);
	case SQLITE_TEXT:
	case SQLITE_BLOB: {
		const auto read = (type == SQLITE_TEXT)
			? +[](sqlite3_stmt *stmt, int index) -> const void* {
				return sqlite3_column_text(stmt, index);
			}
			: &sqlite3_column_blob;
		const auto first = read(&source, column);
		const auto second = read(&destination, column);
		const auto size = sqlite3_column_bytes(&source, column);
		return size == sqlite3_column_bytes(&destination, column)
			&& (!size || (first && second && !std::memcmp(first, second, size)));
	}
	}
	return false;
}

bool CopyTable(
		sqlite3 &legacy,
		const ArchivePartitionTarget &target,
		const char *table) {
	const auto select = std::string("SELECT * FROM ") + table;
	auto source = Prepare(legacy, select + " WHERE userId = ?1 ORDER BY fakeId");
	auto destination = Prepare(*target.database, select + " ORDER BY fakeId");
	if (!source || !destination
		|| sqlite3_bind_int64(source.get(), 1, target.userId) != SQLITE_OK
		|| !MatchingColumns(*source, *destination)) {
		return false;
	}
	const auto existing = sqlite3_step(destination.get());
	if (existing != SQLITE_DONE && existing != SQLITE_ROW) {
		return false;
	}
	if (existing == SQLITE_DONE) {
		const auto count = sqlite3_column_count(source.get());
		auto query = std::string("INSERT INTO ") + table + " VALUES (?";
		for (auto column = 1; column != count; ++column) {
			query += ",?";
		}
		auto insert = Prepare(*target.database, query + ')');
		if (!insert) {
			return false;
		}
		auto result = int();
		while ((result = sqlite3_step(source.get())) == SQLITE_ROW) {
			for (auto column = 0; column != count; ++column) {
				const auto value = sqlite3_column_value(source.get(), column);
				if (!value || sqlite3_bind_value(insert.get(), column + 1, value) != SQLITE_OK) {
					return false;
				}
			}
			if (sqlite3_step(insert.get()) != SQLITE_DONE
				|| sqlite3_reset(insert.get()) != SQLITE_OK) {
				return false;
			}
		}
		if (result != SQLITE_DONE
			|| sqlite3_reset(source.get()) != SQLITE_OK
			|| sqlite3_reset(destination.get()) != SQLITE_OK) {
			return false;
		}
	} else if (sqlite3_reset(destination.get()) != SQLITE_OK) {
		return false;
	}
	auto sourceResult = int();
	while ((sourceResult = sqlite3_step(source.get())) == SQLITE_ROW) {
		if (sqlite3_step(destination.get()) != SQLITE_ROW) {
			return false;
		}
		for (auto column = 0; column != sqlite3_column_count(source.get()); ++column) {
			if (!SameValue(*source, *destination, column)) {
				return false;
			}
		}
	}
	return sourceResult == SQLITE_DONE
		&& sqlite3_step(destination.get()) == SQLITE_DONE;
}

} // namespace

ArchivePartitionResult StageLegacyArchivePartitions(
		sqlite3 &legacy,
		std::span<const ArchivePartitionTarget> targets) {
	using Result = ArchivePartitionResult;
	if (sqlite3_db_readonly(&legacy, "main") != 1) {
		return Result::InvalidSource;
	}
	auto source = Transaction(legacy);
	if (!source.active()) {
		return Result::ReadWriteFailed;
	}
	auto owners = std::set<int64_t>();
	auto databases = std::set<sqlite3*>();
	for (const auto &target : targets) {
		if (target.userId <= 0 || !owners.insert(target.userId).second
			|| !target.database || !databases.insert(target.database).second
			|| sqlite3_db_readonly(target.database, "main") != 0
			|| !CipherEnabled(*target.database)) {
			return Result::InvalidTarget;
		}
	}
	const auto checked = CheckSource(legacy, owners);
	if (checked != Result::Success) {
		return checked;
	}
	for (const auto &target : targets) {
		auto destination = Transaction(*target.database);
		if (!destination.active()
			|| CheckSource(*target.database, { target.userId }) != Result::Success
			|| !std::ranges::all_of(kAccountTables, [&](const char *table) {
				return CopyTable(legacy, target, table);
			}) || !destination.commit()) {
			return Result::ReadWriteFailed;
		}
	}
	return source.commit() ? Result::Success : Result::ReadWriteFailed;
}

} // namespace Ayu
