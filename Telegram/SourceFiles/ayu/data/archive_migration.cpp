// This is the source code of AyuGram for Desktop.
#include "ayu/data/archive_migration.h"

#include "ayu/libs/sqlite/sqlite3.h"

#include <algorithm>
#include <array>
#include <optional>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <atomic>
#include <chrono>
#include <windows.h>
#else
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Ayu {
namespace {

namespace Fs = std::filesystem;
using ArchiveSqlCipher::Connection;
using ArchiveSqlCipher::OpenMode;
using Result = ArchivePartitionResult;

constexpr auto kArchiveFilename = "archive.db";

enum class Entry {
	Missing,
	Directory,
	File,
	Invalid,
};

Entry Inspect(const Fs::path &path) {
#ifdef _WIN32
	const auto attributes = GetFileAttributesW(path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES) {
		return GetLastError() == ERROR_FILE_NOT_FOUND
			? Entry::Missing
			: Entry::Invalid;
	}
	if (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) {
		return Entry::Invalid;
	}
	return (attributes & FILE_ATTRIBUTE_DIRECTORY) ? Entry::Directory : Entry::File;
#else
	auto error = std::error_code();
	const auto status = Fs::symlink_status(path, error);
	if (status.type() == Fs::file_type::not_found) {
		return Entry::Missing;
	}
	if (error) {
		return Entry::Invalid;
	}
	if (Fs::is_directory(status)) {
		return Entry::Directory;
	}
	return Fs::is_regular_file(status) ? Entry::File : Entry::Invalid;
#endif
}

bool RealDirectory(const Fs::path &path) {
	if (!path.is_absolute()
		|| path.native().find(Fs::path::value_type(0)) != Fs::path::string_type::npos) {
		return false;
	}
	auto current = path.root_path();
	for (const auto &part : path.relative_path()) {
		if (part.empty() || part == "." || part == "..") {
			return false;
		}
		current /= part;
		if (Inspect(current) != Entry::Directory) {
			return false;
		}
	}
	return true;
}

bool ValidLocator(std::string_view locator) {
	return locator.size() == 32
		&& locator.find_first_not_of('0') != std::string_view::npos
		&& std::ranges::all_of(locator, [](char ch) {
			return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
		});
}

bool ValidTargets(std::span<const LegacyArchiveFileTarget> targets) {
	auto ids = std::set<int64_t>();
	auto locators = std::set<std::string>();
	for (auto i = size_t(0); i != targets.size(); ++i) {
		const auto &target = targets[i];
		if (target.userId <= 0 || !ids.insert(target.userId).second
			|| !ValidLocator(target.locator)
			|| !locators.insert(target.locator).second
			|| std::ranges::all_of(target.key, [](auto value) { return value == std::byte(0); })
			|| std::ranges::any_of(targets.first(i), [&](const auto &earlier) {
				return std::ranges::equal(earlier.key, target.key);
			})) {
			return false;
		}
	}
	return true;
}

bool ValidAccount(const Fs::path &root) {
	return RealDirectory(root)
		&& Inspect(root / "auths") == Entry::File
		&& Inspect(root / "data") == Entry::Directory;
}

bool ValidArchiveDirectory(const Fs::path &directory) {
	const auto kind = Inspect(directory);
	if (kind == Entry::Missing) {
		return true;
	} else if (kind != Entry::Directory) {
		return false;
	}
	auto error = std::error_code();
	auto entries = Fs::directory_iterator(directory, error);
	const auto end = Fs::directory_iterator();
	while (!error && entries != end) {
		if (entries->path().filename() != kArchiveFilename
			|| Inspect(entries->path()) != Entry::File) {
			return false;
		}
		entries.increment(error);
	}
	return !error;
}

bool SyncDirectory(const Fs::path &directory) {
#ifdef _WIN32
	return Inspect(directory) == Entry::Directory;
#else
	const auto fd = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	const auto result = fsync(fd) == 0;
	close(fd);
	return result;
#endif
}

Fs::path CreateStageDirectory(const Fs::path &root) {
#ifdef _WIN32
	static auto counter = std::atomic<uint64_t>();
	const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
	const auto directory = root / (".archive-stage-"
		+ std::to_string(GetCurrentProcessId())
		+ '-' + std::to_string(ticks)
		+ '-' + std::to_string(counter.fetch_add(1, std::memory_order_relaxed)));
	return CreateDirectoryW(directory.c_str(), nullptr) ? directory : Fs::path();
#else
	auto directory = (root / ".archive-stage-XXXXXX").native();
	return mkdtemp(directory.data()) ? Fs::path(std::move(directory)) : Fs::path();
#endif
}

class StageDirectory final {
public:
	explicit StageDirectory(const Fs::path &root) : path(CreateStageDirectory(root)) {
	}
	StageDirectory(const StageDirectory &) = delete;
	StageDirectory &operator=(const StageDirectory &) = delete;
	~StageDirectory() {
		if (!path.empty()) {
			auto error = std::error_code();
			Fs::remove_all(path, error);
		}
	}

	const Fs::path path;

};

#ifndef _WIN32
constexpr auto kDirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

struct DirectoryDescriptor final {
	int fd = -1;
	~DirectoryDescriptor() {
		if (fd >= 0) {
			close(fd);
		}
	}
	DirectoryDescriptor(const DirectoryDescriptor &) = delete;
	DirectoryDescriptor &operator=(const DirectoryDescriptor &) = delete;
	explicit DirectoryDescriptor(int value) : fd(value) {
	}
};

int OpenDirectory(const Fs::path &path) {
	auto fd = open(path.root_path().c_str(), kDirectoryFlags);
	for (const auto &part : path.relative_path()) {
		if (fd < 0) {
			break;
		}
		const auto child = openat(fd, part.c_str(), kDirectoryFlags);
		close(fd);
		fd = child;
	}
	return fd;
}
#endif

bool PublishFile(const Fs::path &temporary, const Fs::path &finalPath) {
	const auto directory = finalPath.parent_path();
	if (!ValidAccount(directory.parent_path()) || !ValidArchiveDirectory(directory)) {
		return false;
	}
#ifdef _WIN32
	auto error = std::error_code();
	Fs::create_directory(directory, error);
	return !error && RealDirectory(directory)
		&& MoveFileExW(temporary.c_str(), finalPath.c_str(), MOVEFILE_WRITE_THROUGH);
#else
	const auto account = DirectoryDescriptor(OpenDirectory(directory.parent_path()));
	const auto stage = DirectoryDescriptor(OpenDirectory(temporary.parent_path()));
	if (account.fd < 0 || stage.fd < 0
		|| (mkdirat(account.fd, "user", S_IRWXU) != 0 && errno != EEXIST)) {
		return false;
	}
	const auto output = DirectoryDescriptor(openat(account.fd, "user", kDirectoryFlags));
	struct stat info = {};
	return output.fd >= 0
		&& fstatat(stage.fd, kArchiveFilename, &info, AT_SYMLINK_NOFOLLOW) == 0
		&& S_ISREG(info.st_mode)
		&& linkat(stage.fd, kArchiveFilename, output.fd, kArchiveFilename, 0) == 0;
#endif
}

bool SafeArchiveSidecars(const Fs::path &path) {
	for (const auto suffix : { "-wal", "-shm", "-journal" }) {
		auto sidecar = path;
		sidecar += suffix;
		const auto kind = Inspect(sidecar);
		if (kind != Entry::File && kind != Entry::Missing) {
			return false;
		}
	}
	return true;
}

Connection OpenLegacy(const Fs::path &path) {
	if (Inspect(path) != Entry::File || !SafeArchiveSidecars(path)) {
		return nullptr;
	}
	const auto name = path.u8string();
	auto raw = static_cast<sqlite3*>(nullptr);
	const auto result = sqlite3_open_v2(
		reinterpret_cast<const char*>(name.c_str()),
		&raw,
		SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_PRIVATECACHE,
		nullptr);
	auto connection = Connection(raw);
	return (result == SQLITE_OK) ? std::move(connection) : Connection();
}

bool Execute(sqlite3 &database, const char *sql) {
	return sqlite3_exec(&database, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

using Schema = std::vector<std::array<std::string, 4>>;

bool HasOnlyArchiveOwner(sqlite3 &database, int64_t userId) {
	constexpr auto kTables = std::array{
		"DeletedDialog",
		"DeletedMessage",
		"EditedMessage",
		"SpyMessageContentsRead",
		"SpyMessageRead",
	};
	return std::ranges::all_of(kTables, [&](const char *table) {
		const auto sql = std::string("SELECT 1 FROM ") + table
			+ " WHERE userId IS NOT ?1 OR typeof(userId) != 'integer' LIMIT 1";
		auto raw = static_cast<sqlite3_stmt*>(nullptr);
		const auto prepared = sqlite3_prepare_v2(&database, sql.c_str(), -1, &raw, nullptr);
		const auto statement = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>(
			raw, &sqlite3_finalize);
		return prepared == SQLITE_OK
			&& sqlite3_bind_int64(statement.get(), 1, userId) == SQLITE_OK
			&& sqlite3_step(statement.get()) == SQLITE_DONE;
	});
}

std::optional<Schema> ReadSchema(sqlite3 &database) {
	auto raw = static_cast<sqlite3_stmt*>(nullptr);
	const auto prepared = sqlite3_prepare_v2(
		&database,
		"SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema"
		" UNION ALL SELECT 'version', CAST(id AS TEXT), CAST(version AS TEXT), ''"
		" FROM SchemaVersion ORDER BY 1, 2",
		-1,
		&raw,
		nullptr);
	const auto statement = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>(
		raw, &sqlite3_finalize);
	if (prepared != SQLITE_OK) {
		return std::nullopt;
	}
	auto schema = Schema();
	auto result = SQLITE_OK;
	while ((result = sqlite3_step(statement.get())) == SQLITE_ROW) {
		auto row = Schema::value_type();
		for (auto i = size_t(0); i != row.size(); ++i) {
			const auto text = sqlite3_column_text(statement.get(), int(i));
			if (!text) {
				return std::nullopt;
			}
			row[i] = reinterpret_cast<const char*>(text);
		}
		schema.push_back(std::move(row));
	}
	return (result == SQLITE_DONE && !schema.empty())
		? std::optional(std::move(schema))
		: std::nullopt;
}

std::optional<Schema> ExpectedSchema(const std::string &sql) {
	auto raw = static_cast<sqlite3*>(nullptr);
	const auto result = sqlite3_open(":memory:", &raw);
	const auto connection = Connection(raw);
	return (result == SQLITE_OK && Execute(*connection, sql.c_str()))
		? ReadSchema(*connection)
		: std::nullopt;
}

struct StagedArchive final {
	Fs::path destination;
	std::unique_ptr<StageDirectory> staging;
	const LegacyArchiveFileTarget *target = nullptr;
	Connection database;

	[[nodiscard]] Fs::path openPath() const {
		return staging ? (staging->path / kArchiveFilename) : destination;
	}
};

bool OpenForReadback(StagedArchive &archive, const Schema &schema) {
	const auto path = archive.openPath();
	auto error = std::error_code();
	if (Inspect(path) != Entry::File || !Fs::file_size(path, error) || error) {
		return false;
	}
	archive.database = ArchiveSqlCipher::Open(path, OpenMode::ReadOnly, archive.target->key);
	return archive.database && ReadSchema(*archive.database) == schema;
}

Result Partition(sqlite3 &legacy, const std::vector<StagedArchive> &archives) {
	auto targets = std::vector<ArchivePartitionTarget>();
	targets.reserve(archives.size());
	for (const auto &archive : archives) {
		targets.push_back({ archive.target->userId, archive.database.get() });
	}
	return StageLegacyArchivePartitions(legacy, targets);
}

} // namespace

ArchivePartitionResult StageLegacyArchiveFiles(
		const std::filesystem::path &dataDirectory,
		std::span<const LegacyArchiveFileTarget> targets,
		const std::string &schemaSql) {
	const auto data = dataDirectory.has_filename()
		? dataDirectory
		: dataDirectory.parent_path();
	const auto root = data / "profile-sets" / "accounts";
	if (!data.has_filename() || !RealDirectory(root) || !ValidTargets(targets)) {
		return Result::InvalidTarget;
	}
	auto source = OpenLegacy(data / "ayudata.db");
	if (!source) {
		return Result::InvalidSource;
	}
	const auto schema = ExpectedSchema(schemaSql);
	if (!schema) {
		return Result::InvalidTarget;
	}
	auto archives = std::vector<StagedArchive>();
	archives.reserve(targets.size());
	for (const auto &target : targets) {
		const auto account = root / target.locator;
		const auto directory = account / "user";
		if (!ValidAccount(account) || !ValidArchiveDirectory(directory)) {
			return Result::InvalidTarget;
		}
		archives.push_back({ .destination = directory / kArchiveFilename, .target = &target });
	}
	for (auto &archive : archives) {
		if (Inspect(archive.destination.parent_path()) == Entry::Directory
			&& Inspect(archive.destination) != Entry::Missing) {
			if (!OpenForReadback(archive, *schema)) {
				return Result::InvalidTarget;
			}
			continue;
		}
		archive.staging = std::make_unique<StageDirectory>(root);
		if (archive.staging->path.empty()) {
			return Result::ReadWriteFailed;
		}
		archive.database = ArchiveSqlCipher::Open(
			archive.openPath(), OpenMode::ReadWriteOrCreate, archive.target->key);
		if (!archive.database
			|| !Execute(*archive.database, "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
			|| !Execute(*archive.database, schemaSql.c_str())
			|| ReadSchema(*archive.database) != *schema) {
			return Result::InvalidTarget;
		}
	}
	const auto partitioned = Partition(*source, archives);
	if (partitioned != Result::Success) {
		return partitioned;
	}
	for (auto &archive : archives) {
		archive.database.reset();
		if (!OpenForReadback(archive, *schema)) {
			return Result::ReadWriteFailed;
		}
	}
	const auto verified = Partition(*source, archives);
	if (verified != Result::Success) {
		return verified;
	}
	for (auto &archive : archives) {
		archive.database.reset();
		if (archive.staging && !PublishFile(archive.openPath(), archive.destination)) {
			return Result::ReadWriteFailed;
		}
		const auto directory = archive.destination.parent_path();
		if (!SyncDirectory(directory) || !SyncDirectory(directory.parent_path())) {
			return Result::ReadWriteFailed;
		}
	}
	return Result::Success;
}

ArchiveSqlCipher::Connection OpenVerifiedScopedArchive(
		const std::filesystem::path &path,
		int64_t userId,
		ArchiveSqlCipher::Key key,
		const std::string &schemaSql) {
	const auto directory = path.parent_path();
	const auto account = directory.parent_path();
	const auto accounts = account.parent_path();
	auto error = std::error_code();
	if (userId <= 0 || path.filename() != kArchiveFilename
		|| directory.filename() != "user" || accounts.filename() != "accounts"
		|| accounts.parent_path().filename() != "profile-sets"
		|| !ValidLocator(account.filename().string()) || !ValidAccount(account)
		|| !RealDirectory(directory) || Inspect(path) != Entry::File
		|| !Fs::file_size(path, error) || error || !SafeArchiveSidecars(path)) {
		return nullptr;
	}
	auto connection = ArchiveSqlCipher::Open(path, OpenMode::ReadWrite, key);
	const auto expected = ExpectedSchema(schemaSql);
	if (!connection || !expected || ReadSchema(*connection) != expected
		|| !HasOnlyArchiveOwner(*connection, userId)) {
		return nullptr;
	}
	return connection;
}

} // namespace Ayu
