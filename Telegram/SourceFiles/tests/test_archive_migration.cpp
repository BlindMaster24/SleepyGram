#include "ayu/data/archive_migration.h"

#include "ayu/libs/sqlite/sqlite3.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iterator>

namespace {

using namespace Ayu;
namespace Fs = std::filesystem;
using Result = ArchivePartitionResult;

constexpr auto kTables = std::array{
	"DeletedDialog", "DeletedMessage", "EditedMessage", "SpyMessageContentsRead", "SpyMessageRead",
};
constexpr auto kFirst = "1111ac2444293a85533a373f247b25c0";
constexpr auto kSecond = "22228effc44571a77424d2fbc4575223";
constexpr auto kPlaintext = "fixture archive row for account one";

int failures = 0;

void Check(const char *label, bool condition) {
	std::printf("%s %s\n", condition ? "PASS" : "FAIL", label);
	failures += !condition;
}

std::array<std::byte, ArchiveSqlCipher::kKeySize> Key(unsigned char value) {
	auto key = std::array<std::byte, ArchiveSqlCipher::kKeySize>();
	key.fill(std::byte(value));
	return key;
}

std::string Schema() {
	auto sql = std::string(
		"CREATE TABLE SchemaVersion(id INTEGER PRIMARY KEY, version INTEGER);"
		"INSERT INTO SchemaVersion VALUES(1, 1);"
		"CREATE TABLE RegexFilter(text TEXT);"
		"CREATE TABLE RegexFilterGlobalExclusion(dialogId INTEGER);");
	for (const auto table : kTables) {
		sql += std::string("CREATE TABLE ") + table
			+ "(fakeId INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER, payload BLOB, note TEXT);";
	}
	return sql;
}

bool Exec(sqlite3 *database, const std::string &sql) {
	return database && sqlite3_exec(database, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool HasRow(sqlite3 *database, const std::string &query) {
	if (!database) {
		return false;
	}
	auto raw = static_cast<sqlite3_stmt*>(nullptr);
	const auto prepared = sqlite3_prepare_v2(database, query.c_str(), -1, &raw, nullptr);
	const auto statement = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>(
		raw, &sqlite3_finalize);
	return prepared == SQLITE_OK && sqlite3_step(statement.get()) == SQLITE_ROW;
}

std::string Bytes(const Fs::path &path) {
	auto stream = std::ifstream(path, std::ios::binary);
	return std::string(std::istreambuf_iterator<char>(stream), {});
}

class Fixture final {
public:
	Fixture()
	: root(Fs::canonical(Fs::temp_directory_path()) / ("sleepy-archive-bridge-"
		+ std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())))
	, tdata(root / "tdata")
	, legacy(tdata / "ayudata.db")
	, owned(Fs::create_directory(root)) {
		if (owned) {
			for (const auto locator : { kFirst, kSecond }) {
				Fs::create_directories(account(locator) / "data");
				std::ofstream(account(locator) / "auths") << "fixture";
			}
		}
	}
	~Fixture() {
		if (owned) {
			auto error = std::error_code();
			Fs::remove_all(root, error);
		}
	}

	[[nodiscard]] Fs::path account(const char *locator) const {
		return tdata / "profile-sets" / "accounts" / locator;
	}
	[[nodiscard]] Fs::path archive(const char *locator) const {
		return account(locator) / "user" / "archive.db";
	}
	[[nodiscard]] std::array<LegacyArchiveFileTarget, 2> targets() const {
		return {{ { 101, kFirst, first }, { 202, kSecond, second } }};
	}
	[[nodiscard]] ArchiveSqlCipher::Connection seed(bool wal = false) const {
		auto raw = static_cast<sqlite3*>(nullptr);
		const auto result = sqlite3_open(legacy.string().c_str(), &raw);
		auto connection = ArchiveSqlCipher::Connection(raw);
		if (result != SQLITE_OK || (wal && !Exec(raw, "PRAGMA journal_mode=WAL;"))
			|| !Exec(raw, Schema())) {
			return nullptr;
		}
		for (const auto table : kTables) {
			if (!Exec(raw, std::string("INSERT INTO ") + table
				+ " VALUES(9,101,x'0042FF','" + kPlaintext + "'),(16,202,x'0033',NULL);")) {
				return nullptr;
			}
		}
		return connection;
	}

	const Fs::path root;
	const Fs::path tdata;
	const Fs::path legacy;
	const bool owned;
	const std::array<std::byte, ArchiveSqlCipher::kKeySize> first = Key(3);
	const std::array<std::byte, ArchiveSqlCipher::kKeySize> second = Key(4);

};

void StageAndReopen() {
	const auto fixture = Fixture();
	if (!fixture.owned) {
		Check("archive-migration-fixture-created", false);
		return;
	}
	const auto source = fixture.seed(true);
	Check("archive-legacy-fixture-includes-wal", source && Fs::exists(fixture.legacy.string() + "-wal"));
	const auto original = Bytes(fixture.legacy);
	const auto wal = Bytes(fixture.legacy.string() + "-wal");
	Check("archive-stages-both-account-files", StageLegacyArchiveFiles(
		fixture.tdata, fixture.targets(), Schema()) == Result::Success);
	Check("archive-preserves-legacy-main-and-wal-bytes",
		Bytes(fixture.legacy) == original && Bytes(fixture.legacy.string() + "-wal") == wal);
	using enum ArchiveSqlCipher::OpenMode;
	auto first = ArchiveSqlCipher::Open(fixture.archive(kFirst), ReadOnly, fixture.first);
	auto second = ArchiveSqlCipher::Open(fixture.archive(kSecond), ReadOnly, fixture.second);
	Check("archive-reopened-files-have-distinct-keys",
		first && second && !ArchiveSqlCipher::Open(fixture.archive(kFirst), ReadOnly, fixture.second));
	for (const auto table : kTables) {
		const auto select = std::string("SELECT 1 FROM ") + table;
		Check("archive-partition-preserves-rowid-and-blob-or-null",
			HasRow(first.get(), select + " WHERE fakeId=9 AND userId=101 AND payload=x'0042FF'")
			&& !HasRow(first.get(), select + " WHERE userId=202")
			&& HasRow(second.get(), select + " WHERE fakeId=16 AND userId=202 AND note IS NULL")
			&& !HasRow(second.get(), select + " WHERE userId=101"));
	}
	const auto encrypted = Bytes(fixture.archive(kFirst));
	Check("archive-published-file-hides-fixture-plaintext",
		!encrypted.empty() && encrypted.find(kPlaintext) == std::string::npos);
	Check("archive-retry-verifies-without-changing-published-file", StageLegacyArchiveFiles(
		fixture.tdata / "", fixture.targets(), Schema()) == Result::Success
		&& Bytes(fixture.archive(kFirst)) == encrypted);
	Check("archive-stale-source-fixture-written", Exec(source.get(),
		"UPDATE EditedMessage SET note='changed after staging' WHERE userId=101"));
	Check("archive-stale-retry-refuses-to-rewrite-published-file", StageLegacyArchiveFiles(
		fixture.tdata, fixture.targets(), Schema()) != Result::Success
		&& Bytes(fixture.archive(kFirst)) == encrypted);
}

void InvalidFilesNeverPublish() {
	const auto fixture = Fixture();
	if (!fixture.owned) {
		Check("archive-invalid-input-fixture-created", false);
		return;
	}
	Check("archive-absent-source-is-not-created", StageLegacyArchiveFiles(
		fixture.tdata, fixture.targets(), Schema()) == Result::InvalidSource
		&& !Fs::exists(fixture.legacy));
	const auto source = fixture.seed();
	Check("archive-invalid-input-legacy-fixture-seeded", bool(source));
	const auto target = fixture.archive(kSecond);
	Fs::create_directory(target.parent_path());
	std::ofstream(target).close();
	Check("archive-rejects-preexisting-plain-empty-file", StageLegacyArchiveFiles(
		fixture.tdata, fixture.targets(), Schema()) == Result::InvalidTarget
		&& Fs::is_regular_file(target) && Fs::file_size(target) == 0
		&& !Fs::exists(fixture.archive(kFirst)));
	Fs::remove(target);
	const auto sidecar = fixture.legacy.string() + "-wal";
	auto linked = std::error_code();
	Fs::create_symlink(fixture.legacy, sidecar, linked);
	if (!linked) {
		Check("archive-rejects-linked-legacy-sidecar", StageLegacyArchiveFiles(
			fixture.tdata, fixture.targets(), Schema()) == Result::InvalidSource
			&& Fs::is_symlink(sidecar));
		Fs::remove(sidecar);
	}
	const auto outside = fixture.root / "unrelated";
	Fs::create_directory(outside);
	std::ofstream(outside / "sentinel") << "keep";
	Fs::remove(target.parent_path());
	Fs::create_directory_symlink(outside, target.parent_path(), linked);
	if (!linked) {
		Check("archive-rejects-destination-directory-link", StageLegacyArchiveFiles(
			fixture.tdata, fixture.targets(), Schema()) == Result::InvalidTarget
			&& !Fs::exists(outside / "archive.db") && Bytes(outside / "sentinel") == "keep");
		Fs::remove(target.parent_path());
	}
	Check("archive-unowned-filter-fixture-written", Exec(source.get(),
		"INSERT INTO RegexFilter VALUES('fixture rule')"));
	Check("archive-unassigned-filters-do-not-publish-account-files", StageLegacyArchiveFiles(
		fixture.tdata, fixture.targets(), Schema()) == Result::UnassignedFilters
		&& !Fs::exists(fixture.archive(kFirst)) && !Fs::exists(target));
	Check("archive-unassigned-account-fixture-written", Exec(source.get(),
		"DELETE FROM RegexFilter; INSERT INTO EditedMessage VALUES(17,303,x'00',NULL);"));
	Check("archive-unassigned-rows-do-not-publish-account-files", StageLegacyArchiveFiles(
		fixture.tdata, fixture.targets(), Schema()) == Result::UnassignedRows
		&& !Fs::exists(fixture.archive(kFirst)) && !Fs::exists(target));
}

} // namespace

int main() {
	StageAndReopen();
	InvalidFilesNeverPublish();
	return failures ? 1 : 0;
}
