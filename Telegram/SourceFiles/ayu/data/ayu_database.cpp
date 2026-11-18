// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#include "ayu/data/ayu_database.h"

#include "ayu/data/entities.h"
#include "ayu/libs/sqlite/sqlite_orm.h"
#include "base/unixtime.h"

#include <algorithm>
#include <map>
#include <mutex>
#include <set>
#include <type_traits>
#include <utility>

using namespace sqlite_orm;

std::mutex databaseMutex;

namespace {

constexpr auto kLatestSchemaVersion = 1;

auto MakeStorage(std::string path) {
	return make_storage(
		std::move(path),
		make_table<SchemaVersion>(
			"SchemaVersion",
			make_column("id", &SchemaVersion::id, primary_key()),
			make_column("version", &SchemaVersion::version)
		),
		make_index("idx_deleted_message_userId_dialogId_topicId_messageId",
				   column<DeletedMessage>(&DeletedMessage::userId),
				   column<DeletedMessage>(&DeletedMessage::dialogId),
				   column<DeletedMessage>(&DeletedMessage::topicId),
				   column<DeletedMessage>(&DeletedMessage::messageId)),
		make_index("idx_edited_message_userId_dialogId_messageId",
				   column<EditedMessage>(&EditedMessage::userId),
				   column<EditedMessage>(&EditedMessage::dialogId),
				   column<EditedMessage>(&EditedMessage::messageId)),
		make_index("idx_edited_archive_search",
				   column<EditedMessage>(&EditedMessage::userId),
				   column<EditedMessage>(&EditedMessage::editDate),
				   column<EditedMessage>(&EditedMessage::fakeId)),
		make_index("idx_deleted_archive_search",
				   column<DeletedMessage>(&DeletedMessage::userId),
				   column<DeletedMessage>(&DeletedMessage::date),
				   column<DeletedMessage>(&DeletedMessage::fakeId)),
		make_table<DeletedMessage>(
			"DeletedMessage",
			make_column("fakeId", &DeletedMessage::fakeId, primary_key().autoincrement()),
			make_column("userId", &DeletedMessage::userId),
			make_column("dialogId", &DeletedMessage::dialogId),
			make_column("groupedId", &DeletedMessage::groupedId),
			make_column("peerId", &DeletedMessage::peerId),
			make_column("peerType", &DeletedMessage::peerType, default_value(0)),
			make_column("fromId", &DeletedMessage::fromId),
			make_column("topicId", &DeletedMessage::topicId),
			make_column("messageId", &DeletedMessage::messageId),
			make_column("date", &DeletedMessage::date),
			make_column("flags", &DeletedMessage::flags),
			make_column("editDate", &DeletedMessage::editDate),
			make_column("views", &DeletedMessage::views),
			make_column("fwdFlags", &DeletedMessage::fwdFlags),
			make_column("fwdFromId", &DeletedMessage::fwdFromId),
			make_column("fwdName", &DeletedMessage::fwdName),
			make_column("fwdDate", &DeletedMessage::fwdDate),
			make_column("fwdPostAuthor", &DeletedMessage::fwdPostAuthor),
			make_column("replyFlags", &DeletedMessage::replyFlags),
			make_column("replyMessageId", &DeletedMessage::replyMessageId),
			make_column("replyPeerId", &DeletedMessage::replyPeerId),
			make_column("replyTopId", &DeletedMessage::replyTopId),
			make_column("replyForumTopic", &DeletedMessage::replyForumTopic),
			make_column("replySerialized", &DeletedMessage::replySerialized),
			make_column("entityCreateDate", &DeletedMessage::entityCreateDate),
			make_column("text", &DeletedMessage::text),
			make_column("textEntities", &DeletedMessage::textEntities),
			make_column("mediaPath", &DeletedMessage::mediaPath),
			make_column("hqThumbPath", &DeletedMessage::hqThumbPath),
			make_column("documentType", &DeletedMessage::documentType),
			make_column("documentSerialized", &DeletedMessage::documentSerialized),
			make_column("thumbsSerialized", &DeletedMessage::thumbsSerialized),
			make_column("documentAttributesSerialized", &DeletedMessage::documentAttributesSerialized),
			make_column("mimeType", &DeletedMessage::mimeType)
		),
		make_table<EditedMessage>(
			"EditedMessage",
			make_column("fakeId", &EditedMessage::fakeId, primary_key().autoincrement()),
			make_column("userId", &EditedMessage::userId),
			make_column("dialogId", &EditedMessage::dialogId),
			make_column("groupedId", &EditedMessage::groupedId),
			make_column("peerId", &EditedMessage::peerId),
			make_column("peerType", &EditedMessage::peerType, default_value(0)),
			make_column("fromId", &EditedMessage::fromId),
			make_column("topicId", &EditedMessage::topicId),
			make_column("messageId", &EditedMessage::messageId),
			make_column("date", &EditedMessage::date),
			make_column("flags", &EditedMessage::flags),
			make_column("editDate", &EditedMessage::editDate),
			make_column("views", &EditedMessage::views),
			make_column("fwdFlags", &EditedMessage::fwdFlags),
			make_column("fwdFromId", &EditedMessage::fwdFromId),
			make_column("fwdName", &EditedMessage::fwdName),
			make_column("fwdDate", &EditedMessage::fwdDate),
			make_column("fwdPostAuthor", &EditedMessage::fwdPostAuthor),
			make_column("replyFlags", &EditedMessage::replyFlags),
			make_column("replyMessageId", &EditedMessage::replyMessageId),
			make_column("replyPeerId", &EditedMessage::replyPeerId),
			make_column("replyTopId", &EditedMessage::replyTopId),
			make_column("replyForumTopic", &EditedMessage::replyForumTopic),
			make_column("replySerialized", &EditedMessage::replySerialized),
			make_column("entityCreateDate", &EditedMessage::entityCreateDate),
			make_column("text", &EditedMessage::text),
			make_column("textEntities", &EditedMessage::textEntities),
			make_column("mediaPath", &EditedMessage::mediaPath),
			make_column("hqThumbPath", &EditedMessage::hqThumbPath),
			make_column("documentType", &EditedMessage::documentType),
			make_column("documentSerialized", &EditedMessage::documentSerialized),
			make_column("thumbsSerialized", &EditedMessage::thumbsSerialized),
			make_column("documentAttributesSerialized", &EditedMessage::documentAttributesSerialized),
			make_column("mimeType", &EditedMessage::mimeType)
		),
		make_table<DeletedDialog>(
			"DeletedDialog",
			make_column("fakeId", &DeletedDialog::fakeId, primary_key().autoincrement()),
			make_column("userId", &DeletedDialog::userId),
			make_column("dialogId", &DeletedDialog::dialogId),
			make_column("peerId", &DeletedDialog::peerId),
			make_column("folderId", &DeletedDialog::folderId),
			make_column("topMessage", &DeletedDialog::topMessage),
			make_column("lastMessageDate", &DeletedDialog::lastMessageDate),
			make_column("flags", &DeletedDialog::flags),
			make_column("entityCreateDate", &DeletedDialog::entityCreateDate)
		),
		make_table<RegexFilter>(
			"RegexFilter",
			make_column("id", &RegexFilter::id, primary_key()),
			make_column("text", &RegexFilter::text),
			make_column("enabled", &RegexFilter::enabled),
			make_column("reversed", &RegexFilter::reversed),
			make_column("caseInsensitive", &RegexFilter::caseInsensitive),
			make_column("dialogId", &RegexFilter::dialogId)
		),
		make_table<RegexFilterGlobalExclusion>(
			"RegexFilterGlobalExclusion",
			make_column("fakeId", &RegexFilterGlobalExclusion::fakeId, primary_key().autoincrement()),
			make_column("dialogId", &RegexFilterGlobalExclusion::dialogId),
			make_column("filterId", &RegexFilterGlobalExclusion::filterId)
		),
		make_table<SpyMessageRead>(
			"SpyMessageRead",
			make_column("fakeId", &SpyMessageRead::fakeId, primary_key().autoincrement()),
			make_column("userId", &SpyMessageRead::userId),
			make_column("dialogId", &SpyMessageRead::dialogId),
			make_column("messageId", &SpyMessageRead::messageId),
			make_column("entityCreateDate", &SpyMessageRead::entityCreateDate)
		),
		make_table<SpyMessageContentsRead>(
			"SpyMessageContentsRead",
			make_column("fakeId", &SpyMessageContentsRead::fakeId, primary_key().autoincrement()),
			make_column("userId", &SpyMessageContentsRead::userId),
			make_column("dialogId", &SpyMessageContentsRead::dialogId),
			make_column("messageId", &SpyMessageContentsRead::messageId),
			make_column("entityCreateDate", &SpyMessageContentsRead::entityCreateDate)
		)
	);
}

std::string ArchiveSchemaSql() {
	auto schema = MakeStorage("archive-schema");
	const auto &objects = obtain_db_objects(schema);
	using Objects = std::remove_cvref_t<decltype(objects)>;
	const auto context = sqlite_orm::internal::serializer_context<Objects>{ objects };
	auto sql = std::string();
	sqlite_orm::internal::iterate_tuple<true>(objects, [&](const auto &object) {
		sql += sqlite_orm::internal::serialize(object, context);
		sql += ';';
	});
	sql += "INSERT INTO SchemaVersion(id, version) VALUES(1,"
		+ std::to_string(kLatestSchemaVersion) + ");";
	return sql;
}

using ArchiveStorage = decltype(MakeStorage(std::string()));

struct ArchiveConnectionHolder final : sqlite_orm::internal::connection_holder {
	static void Adopt(connection_holder &holder, sqlite3 *database) {
		holder.*(&ArchiveConnectionHolder::db) = database;
		holder.*(&ArchiveConnectionHolder::_retain_count) = 1;
	}
};

class ScopedArchiveStorage final : public ArchiveStorage {
public:
	ScopedArchiveStorage(ArchiveStorage schema, Ayu::ArchiveSqlCipher::Connection opened)
	: ArchiveStorage(schema)
	, _opened(std::move(opened)) {
		// Retaining the native handle keeps sqlite_orm from reopening the file without its key.
		ArchiveConnectionHolder::Adopt(*connection, _opened.get());
	}

private:
	Ayu::ArchiveSqlCipher::Connection _opened;

};

struct ArchiveRuntime final {
	bool scoped = false;
	uint64_t generation = 1;
	std::unique_ptr<ArchiveStorage> legacy;
	std::map<ID, std::unique_ptr<ScopedArchiveStorage>> accounts;
};

ArchiveRuntime archiveRuntime;

ArchiveStorage &LegacyStorage() {
	if (!archiveRuntime.legacy) {
		archiveRuntime.legacy = std::make_unique<ArchiveStorage>(
			MakeStorage("./tdata/ayudata.db"));
	}
	return *archiveRuntime.legacy;
}

ArchiveStorage *ArchiveForUser(ID userId) {
	if (!archiveRuntime.scoped) {
		return &LegacyStorage();
	}
	const auto i = archiveRuntime.accounts.find(userId);
	return (i == archiveRuntime.accounts.end()) ? nullptr : i->second.get();
}

bool CurrentArchiveRead(AyuDatabase::ArchiveReadToken token) {
	return token.generation == archiveRuntime.generation
		&& (!archiveRuntime.scoped || archiveRuntime.accounts.contains(token.userId));
}

void CloseScopedArchiveBatch() {
	archiveRuntime.accounts.clear();
	++archiveRuntime.generation;
}

void ReserveScopedArchiveRuntime() {
	if (!archiveRuntime.scoped) {
		archiveRuntime.scoped = true;
		++archiveRuntime.generation;
		archiveRuntime.legacy.reset();
	}
}

bool DistinctArchiveAccounts(std::span<const AyuDatabase::ScopedArchiveAccount> accounts) {
	auto users = std::set<ID>();
	for (auto i = size_t(0); i != accounts.size(); ++i) {
		const auto &account = accounts[i];
		if (account.userId <= 0 || !users.insert(account.userId).second
			|| std::ranges::any_of(accounts.first(i), [&](const auto &earlier) {
				auto error = std::error_code();
				return std::ranges::equal(account.key, earlier.key)
					|| std::filesystem::equivalent(account.path, earlier.path, error)
					|| error;
			})) {
			return false;
		}
	}
	return true;
}

void RotateLegacyDatabase() {
	const auto time = base::unixtime::now();

	if (QFile::exists("./tdata/ayudata.db")) {
		QFile::rename("./tdata/ayudata.db", QString("./tdata/ayudata_%1.db").arg(time));
	}

	if (QFile::exists("./tdata/ayudata.db-shm")) {
		QFile::rename("./tdata/ayudata.db-shm", QString("./tdata/ayudata_%1.db-shm").arg(time));
	}

	if (QFile::exists("./tdata/ayudata.db-wal")) {
		QFile::rename("./tdata/ayudata.db-wal", QString("./tdata/ayudata_%1.db-wal").arg(time));
	}
}

} // namespace

namespace AyuMigrations {

void migrateToV1(ArchiveStorage &storage) {
	// drop RegexFilter table as we've added primary_key()
	try {
		storage.drop_table_if_exists("RegexFilter");
		LOG(("Migration to V1 successful."));
	} catch (const std::exception &ex) {
		LOG(("Migration to V1 failed: %1").arg(ex.what()));
	}
}

}

void runMigrations(ArchiveStorage &storage) {
	const std::map<int, Fn<void(ArchiveStorage &)>> migrations = {
		{1, AyuMigrations::migrateToV1},
	};

	int currentVersion = 0;
	try {
		if (auto versionRow = storage.get_pointer<SchemaVersion>(1)) {
			currentVersion = versionRow->version;
		} else {
			storage.insert(SchemaVersion{1, 0});
		}
	} catch (...) {
		LOG(("No SchemaVersion, assuming 0"));
		storage.insert(SchemaVersion{1, 0});
	}

	if (currentVersion >= kLatestSchemaVersion) {
		LOG(("Database is ok"));
		return;
	}

	LOG(("Database version: %1. Latest version: %2.").arg(currentVersion).arg(kLatestSchemaVersion));

	for (int v = currentVersion + 1; v <= kLatestSchemaVersion; ++v) {
		if (migrations.contains(v)) {
			try {
				LOG(("Migration for version: %1").arg(v));
				storage.begin_transaction();

				migrations.at(v)(storage);

				storage.update_all(set(c(&SchemaVersion::version) = v), where(c(&SchemaVersion::id) == 1));
				storage.commit();
				LOG(("Applied migration for version: %1.").arg(v));
			} catch (...) {
				storage.rollback();
				LOG(("Failed to apply migration for version: %1.").arg(v));
				RotateLegacyDatabase();

				return;
			}
		}
	}
}

namespace AyuDatabase {

ScopedArchiveLease::ScopedArchiveLease(uint64_t generation)
: _generation(generation) {
}

ScopedArchiveLease::ScopedArchiveLease(ScopedArchiveLease &&other) noexcept
: _generation(std::exchange(other._generation, 0)) {
}

ScopedArchiveLease &ScopedArchiveLease::operator=(ScopedArchiveLease &&other) noexcept {
	if (this != &other) {
		release();
		_generation = std::exchange(other._generation, 0);
	}
	return *this;
}

ScopedArchiveLease::~ScopedArchiveLease() {
	release();
}

void ScopedArchiveLease::release() {
	if (_generation) {
		std::lock_guard lock(databaseMutex);
		if (_generation == archiveRuntime.generation) {
			CloseScopedArchiveBatch();
		}
		_generation = 0;
	}
}

void ReserveScopedArchives() {
	std::lock_guard lock(databaseMutex);
	ReserveScopedArchiveRuntime();
}

std::optional<ScopedArchiveLease> InstallScopedArchives(
		std::span<const ScopedArchiveAccount> accounts) {
	std::lock_guard lock(databaseMutex);
	ReserveScopedArchiveRuntime();
	CloseScopedArchiveBatch();
	try {
		if (!DistinctArchiveAccounts(accounts)) {
			return std::nullopt;
		}
		auto prepared = decltype(archiveRuntime.accounts)();
		const auto schema = ArchiveSchemaSql();
		for (const auto &account : accounts) {
			auto opened = Ayu::OpenVerifiedScopedArchive(
				account.path, account.userId, account.key, schema);
			if (!opened) {
				return std::nullopt;
			}
			const auto encoded = account.path.u8string();
			const auto filename = std::string(
				reinterpret_cast<const char*>(encoded.data()), encoded.size());
			prepared.emplace(account.userId, std::make_unique<ScopedArchiveStorage>(
				MakeStorage(filename), std::move(opened)));
		}
		archiveRuntime.accounts = std::move(prepared);
		return ScopedArchiveLease(archiveRuntime.generation);
	} catch (const std::exception &) {
		return std::nullopt;
	}
}

void CloseScopedArchives() {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		CloseScopedArchiveBatch();
	}
}

bool LegacyArchiveFiltersAvailable() {
	std::lock_guard lock(databaseMutex);
	return !archiveRuntime.scoped;
}

std::optional<ArchiveReadToken> CaptureArchiveRead(ID userId) {
	std::lock_guard lock(databaseMutex);
	const auto token = ArchiveReadToken{ userId, archiveRuntime.generation };
	return CurrentArchiveRead(token) ? std::optional(token) : std::nullopt;
}

bool IsArchiveReadCurrent(ArchiveReadToken token) {
	std::lock_guard lock(databaseMutex);
	return CurrentArchiveRead(token);
}

Ayu::ArchivePartitionResult StageLegacyArchivePartitions(
		const std::filesystem::path &dataDirectory,
		std::span<const Ayu::LegacyArchiveFileTarget> targets) {
	std::lock_guard lock(databaseMutex);
	return Ayu::StageLegacyArchiveFiles(dataDirectory, targets, ArchiveSchemaSql());
}

Ayu::ArchivePartitionResult StageEmptyScopedArchivePartitions(
		const std::filesystem::path &dataDirectory,
		std::span<const Ayu::LegacyArchiveFileTarget> targets) {
	std::lock_guard lock(databaseMutex);
	return Ayu::StageEmptyScopedArchiveFiles(dataDirectory, targets, ArchiveSchemaSql());
}

void moveCurrentDatabase() {
	std::lock_guard lock(databaseMutex);
	if (!archiveRuntime.scoped) {
		RotateLegacyDatabase();
	}
}

void initialize() {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return;
	}
	auto &storage = LegacyStorage();
	try {
		storage.sync_schema(true);

		runMigrations(storage);

		storage.sync_schema(true);
	} catch (const std::exception &ex) {
		LOG(("Database initialization failed: %1").arg(ex.what()));
		RotateLegacyDatabase();

		storage.sync_schema(true);
		if (!storage.get_pointer<SchemaVersion>(1)) {
			storage.insert(SchemaVersion{1, 0});
		}
	}

	try {
		storage.open_forever();
	} catch (const std::exception &ex) {
		LOG(("Failed to keep database open: %1").arg(ex.what()));
	}
}

void addEditedMessage(const EditedMessage &message) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(message.userId);
	if (!database) {
		return;
	}
	auto &storage = *database;
	try {
		storage.begin_transaction();
		storage.insert(message);
		storage.commit();
	} catch (std::exception &ex) {
		try {
			storage.rollback();
		} catch (...) {
		}
		LOG(("Failed to save edited message for some reason: %1").arg(ex.what()));
	}
}

std::vector<EditedMessage> getEditedMessages(ID userId, ID dialogId, ID messageId, ID minId, ID maxId, int totalLimit) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	try {
		return storage.get_all<EditedMessage>(
			where(
				column<EditedMessage>(&EditedMessage::userId) == userId and
				column<EditedMessage>(&EditedMessage::dialogId) == dialogId and
				column<EditedMessage>(&EditedMessage::messageId) == messageId and
				(column<EditedMessage>(&EditedMessage::fakeId) > minId or minId == 0) and
				(column<EditedMessage>(&EditedMessage::fakeId) < maxId or maxId == 0)
			),
			order_by(column<EditedMessage>(&EditedMessage::fakeId)).desc(),
			limit(totalLimit)
		);
	} catch (std::exception &ex) {
		LOG(("Failed to get edited messages: %1").arg(ex.what()));
		return {};
	}
}

std::vector<EditedMessage> getEditedMessages(
		ID userId,
		ID dialogId,
		ID topicId,
		ID minId,
		ID maxId,
		int totalLimit,
		const std::string &searchQuery) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	try {
		const auto latestPerMessage = in(
			column<EditedMessage>(&EditedMessage::fakeId),
			select(
				max(column<EditedMessage>(&EditedMessage::fakeId)),
				where(
					column<EditedMessage>(&EditedMessage::userId) == userId and
					column<EditedMessage>(&EditedMessage::dialogId) == dialogId and
					(column<EditedMessage>(&EditedMessage::topicId) == topicId or topicId == 0)),
				group_by(
					column<EditedMessage>(&EditedMessage::messageId),
					column<EditedMessage>(&EditedMessage::topicId))));
		if (searchQuery.empty()) {
			return storage.get_all<EditedMessage>(
				where(
					column<EditedMessage>(&EditedMessage::userId) == userId and
					column<EditedMessage>(&EditedMessage::dialogId) == dialogId and
					(column<EditedMessage>(&EditedMessage::topicId) == topicId or topicId == 0) and
					latestPerMessage and
					(column<EditedMessage>(&EditedMessage::fakeId) > minId or minId == 0) and
					(column<EditedMessage>(&EditedMessage::fakeId) < maxId or maxId == 0)),
				order_by(column<EditedMessage>(&EditedMessage::fakeId)).desc(),
				limit(totalLimit));
		}
		auto escaped = std::string();
		escaped.reserve(searchQuery.size());
		for (const auto c : searchQuery) {
			if (c == '%' || c == '_' || c == '\\') {
				escaped += '\\';
			}
			escaped += c;
		}
		const auto pattern = "%" + escaped + "%";
		return storage.get_all<EditedMessage>(
			where(
				column<EditedMessage>(&EditedMessage::userId) == userId and
				column<EditedMessage>(&EditedMessage::dialogId) == dialogId and
				(column<EditedMessage>(&EditedMessage::topicId) == topicId or topicId == 0) and
				latestPerMessage and
				(column<EditedMessage>(&EditedMessage::fakeId) > minId or minId == 0) and
				(column<EditedMessage>(&EditedMessage::fakeId) < maxId or maxId == 0) and
				like(column<EditedMessage>(&EditedMessage::text), pattern, "\\")),
			order_by(column<EditedMessage>(&EditedMessage::fakeId)).desc(),
			limit(totalLimit));
	} catch (std::exception &ex) {
		LOG(("Failed to get edited messages for dialog: %1").arg(ex.what()));
		return {};
	}
}

std::vector<EditedMessage> getEditedMessageRevisions(
		ID userId,
		ID dialogId,
		ID messageId,
		ID topicId,
		ID minId,
		ID maxId,
		int totalLimit) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	try {
		return storage.get_all<EditedMessage>(
			where(
				column<EditedMessage>(&EditedMessage::userId) == userId and
				column<EditedMessage>(&EditedMessage::dialogId) == dialogId and
				column<EditedMessage>(&EditedMessage::messageId) == messageId and
				(column<EditedMessage>(&EditedMessage::topicId) == topicId or topicId == 0) and
				(column<EditedMessage>(&EditedMessage::fakeId) > minId or minId == 0) and
				(column<EditedMessage>(&EditedMessage::fakeId) < maxId or maxId == 0)),
			order_by(column<EditedMessage>(&EditedMessage::fakeId)).desc(),
			limit(totalLimit));
	} catch (std::exception &ex) {
		LOG(("Failed to get edited message revisions: %1").arg(ex.what()));
		return {};
	}
}

bool hasRevisions(ID userId, ID dialogId, ID messageId) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	try {
		return !storage.select(
			columns(column<EditedMessage>(&EditedMessage::messageId)),
			where(
				column<EditedMessage>(&EditedMessage::userId) == userId and
				column<EditedMessage>(&EditedMessage::dialogId) == dialogId and
				column<EditedMessage>(&EditedMessage::messageId) == messageId
			),
			limit(1)
		).empty();
	} catch (std::exception &ex) {
		LOG(("Failed to check if message has revisions: %1").arg(ex.what()));
		return false;
	}
}

void addDeletedMessage(const DeletedMessage &message) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(message.userId);
	if (!database) {
		return;
	}
	auto &storage = *database;
	try {
		storage.begin_transaction();
		storage.insert(message);
		storage.commit();
	} catch (std::exception &ex) {
		try {
			storage.rollback();
		} catch (...) {
		}
		LOG(("Failed to save edited message for some reason: %1").arg(ex.what()));
	}
}

std::vector<DeletedMessage> getDeletedMessages(ID userId, ID dialogId, ID topicId, ID minId, ID maxId, int totalLimit, const std::string &searchQuery) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	try {
		if (searchQuery.empty()) {
			return storage.get_all<DeletedMessage>(
				where(
					column<DeletedMessage>(&DeletedMessage::userId) == userId and
					column<DeletedMessage>(&DeletedMessage::dialogId) == dialogId and
					(column<DeletedMessage>(&DeletedMessage::topicId) == topicId or topicId == 0) and
					(column<DeletedMessage>(&DeletedMessage::messageId) > minId or minId == 0) and
					(column<DeletedMessage>(&DeletedMessage::messageId) < maxId or maxId == 0)
				),
				order_by(column<DeletedMessage>(&DeletedMessage::messageId)).desc(),
				limit(totalLimit)
			);
		}

		std::string escaped;
		escaped.reserve(searchQuery.size());
		for (const auto c : searchQuery) {
			if (c == '%' || c == '_' || c == '\\') {
				escaped += '\\';
			}
			escaped += c;
		}
		const auto pattern = "%" + escaped + "%";
		return storage.get_all<DeletedMessage>(
			where(
				column<DeletedMessage>(&DeletedMessage::userId) == userId and
				column<DeletedMessage>(&DeletedMessage::dialogId) == dialogId and
				(column<DeletedMessage>(&DeletedMessage::topicId) == topicId or topicId == 0) and
				(column<DeletedMessage>(&DeletedMessage::messageId) > minId or minId == 0) and
				(column<DeletedMessage>(&DeletedMessage::messageId) < maxId or maxId == 0) and
				like(column<DeletedMessage>(&DeletedMessage::text), pattern, "\\")
			),
			order_by(column<DeletedMessage>(&DeletedMessage::messageId)).desc(),
			limit(totalLimit)
		);
	} catch (std::exception &ex) {
		LOG(("Failed to get deleted messages: %1").arg(ex.what()));
		return {};
	}
}

bool hasDeletedMessages(ID userId, ID dialogId, ID topicId) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	try {
		return !storage.select(
			columns(column<DeletedMessage>(&DeletedMessage::dialogId)),
			where(
				column<DeletedMessage>(&DeletedMessage::userId) == userId and
				column<DeletedMessage>(&DeletedMessage::dialogId) == dialogId and
				(column<DeletedMessage>(&DeletedMessage::topicId) == topicId or topicId == 0)
			),
			limit(1)
		).empty();
	} catch (std::exception &ex) {
		LOG(("Failed to check if dialog has deleted message: %1").arg(ex.what()));
		return false;
	}
}

void removeDeletedMessage(ID userId, ID dialogId, ID messageId) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return;
	}
	auto &storage = *database;
	try {
		storage.remove_all<DeletedMessage>(
			where(
				column<DeletedMessage>(&DeletedMessage::userId) == userId and
				column<DeletedMessage>(&DeletedMessage::dialogId) == dialogId and
				column<DeletedMessage>(&DeletedMessage::messageId) == messageId
			)
		);
	} catch (std::exception &ex) {
		LOG(("Failed to remove deleted message: %1").arg(ex.what()));
	}
}

void clearDeletedMessages(ID userId, ID dialogId, ID topicId) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return;
	}
	auto &storage = *database;
	try {
		storage.remove_all<DeletedMessage>(
			where(
				column<DeletedMessage>(&DeletedMessage::userId) == userId and
				column<DeletedMessage>(&DeletedMessage::dialogId) == dialogId and
				(column<DeletedMessage>(&DeletedMessage::topicId) == topicId or topicId == 0)
			)
		);
	} catch (std::exception &) {
	}
}

std::vector<ArchiveSearchResult> searchArchive(
		ID userId,
		const std::string &searchQuery,
		ArchiveSearchType type,
		int dateFrom,
		int dateTo,
		std::optional<ArchiveSearchCursor> cursor,
		int pageLimit,
		std::optional<ArchiveReadToken> read) {
	std::lock_guard lock(databaseMutex);
	if ((archiveRuntime.scoped && !read)
		|| (read && (read->userId != userId || !CurrentArchiveRead(*read)))) {
		return {};
	}
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	const auto pageSize = std::clamp(pageLimit, 1, 100);
	const auto hasCursor = cursor.has_value();
	const auto cursorDate = hasCursor ? cursor->date : 0;
	const auto cursorRowId = hasCursor ? cursor->rowId : 0;
	const auto query = [&] {
		auto escaped = std::string();
		escaped.reserve(searchQuery.size());
		for (const auto c : searchQuery) {
			if (c == '%' || c == '_' || c == '\\') {
				escaped += '\\';
			}
			escaped += c;
		}
		return escaped;
	}();
	const auto wantsEdited = (type != ArchiveSearchType::Deleted);
	const auto wantsDeleted = (type != ArchiveSearchType::Edited);
	try {
		auto result = std::vector<ArchiveSearchResult>();
		if (wantsEdited) {
			const auto continueEditedDate = cursor
				&& cursor->type == ArchiveSearchType::Edited;
			const auto cursorAfter
				= (column<EditedMessage>(&EditedMessage::editDate) < cursorDate)
				|| ((column<EditedMessage>(&EditedMessage::editDate)
					== cursorDate)
					&& (continueEditedDate
						&& column<EditedMessage>(&EditedMessage::fakeId)
							< cursorRowId));
			const auto common = column<EditedMessage>(&EditedMessage::userId)
				== userId and
				(dateFrom == 0
					or column<EditedMessage>(&EditedMessage::editDate) >= dateFrom) and
				(dateTo == 0
					or column<EditedMessage>(&EditedMessage::editDate) <= dateTo) and
				(!hasCursor or cursorAfter);
			auto rows = query.empty()
				? storage.get_all<EditedMessage>(
					where(common),
					multi_order_by(
						order_by(column<EditedMessage>(&EditedMessage::editDate)).desc(),
						order_by(column<EditedMessage>(&EditedMessage::fakeId)).desc()),
					limit(pageSize))
				: storage.get_all<EditedMessage>(
					where(common and like(
						column<EditedMessage>(&EditedMessage::text),
						"%" + query + "%",
						"\\")),
					multi_order_by(
						order_by(column<EditedMessage>(&EditedMessage::editDate)).desc(),
						order_by(column<EditedMessage>(&EditedMessage::fakeId)).desc()),
					limit(pageSize));
			for (const auto &row : rows) {
				result.push_back({
					.type = ArchiveSearchType::Edited,
					.date = row.editDate,
					.rowId = row.fakeId,
					.message = static_cast<AyuMessageBase>(row),
				});
			}
		}
		if (wantsDeleted) {
			const auto continueAfterEditedDate = (type == ArchiveSearchType::All
				&& cursor
				&& cursor->type == ArchiveSearchType::Edited);
			const auto continueDeletedDate = cursor
				&& cursor->type == ArchiveSearchType::Deleted;
			const auto cursorAfter
				= (column<DeletedMessage>(&DeletedMessage::date) < cursorDate)
				|| ((column<DeletedMessage>(&DeletedMessage::date) == cursorDate)
					&& (continueAfterEditedDate
						|| (continueDeletedDate
							&& column<DeletedMessage>(&DeletedMessage::fakeId)
								< cursorRowId)));
			const auto common = column<DeletedMessage>(&DeletedMessage::userId)
				== userId and
				(dateFrom == 0
					or column<DeletedMessage>(&DeletedMessage::date) >= dateFrom) and
				(dateTo == 0
					or column<DeletedMessage>(&DeletedMessage::date) <= dateTo) and
				(!hasCursor or cursorAfter);
			auto rows = query.empty()
				? storage.get_all<DeletedMessage>(
					where(common),
					multi_order_by(
						order_by(column<DeletedMessage>(&DeletedMessage::date)).desc(),
						order_by(column<DeletedMessage>(&DeletedMessage::fakeId)).desc()),
					limit(pageSize))
				: storage.get_all<DeletedMessage>(
					where(common and like(
						column<DeletedMessage>(&DeletedMessage::text),
						"%" + query + "%",
						"\\")),
					multi_order_by(
						order_by(column<DeletedMessage>(&DeletedMessage::date)).desc(),
						order_by(column<DeletedMessage>(&DeletedMessage::fakeId)).desc()),
					limit(pageSize));
			for (const auto &row : rows) {
				result.push_back({
					.type = ArchiveSearchType::Deleted,
					.date = row.date,
					.rowId = row.fakeId,
					.message = static_cast<AyuMessageBase>(row),
				});
			}
		}
		std::ranges::sort(result, [](const auto &a, const auto &b) {
			if (a.date != b.date) {
				return a.date > b.date;
			} else if (a.type != b.type) {
				return a.type == ArchiveSearchType::Edited;
			}
			return a.rowId > b.rowId;
		});
		if (result.size() > pageSize) {
			result.resize(pageSize);
		}
		return result;
	} catch (const std::exception &ex) {
		LOG(("Failed to search archived messages: %1").arg(ex.what()));
		return {};
	}
}

ArchiveBackupCounts archiveBackupCounts(ID userId) {
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	try {
		return {
			.edited = int(storage.count<EditedMessage>(
				where(column<EditedMessage>(&EditedMessage::userId) == userId))),
			.deleted = int(storage.count<DeletedMessage>(
				where(column<DeletedMessage>(&DeletedMessage::userId) == userId))),
		};
	} catch (const std::exception &ex) {
		LOG(("Failed to count archived messages: %1").arg(ex.what()));
		return {};
	}
}

std::optional<ArchiveBackupSnapshot> archiveBackupSnapshot(
		ID userId,
		int maxRows) {
	if (maxRows <= 0) {
		return std::nullopt;
	}
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	try {
		auto result = ArchiveBackupSnapshot();
		result.edited = storage.get_all<EditedMessage>(
			where(column<EditedMessage>(&EditedMessage::userId) == userId),
			order_by(column<EditedMessage>(&EditedMessage::fakeId)),
			limit(maxRows));
		const auto remaining = maxRows - int(result.edited.size());
		if (remaining <= 0) {
			const auto editedCount = storage.count<EditedMessage>(
				where(column<EditedMessage>(&EditedMessage::userId) == userId));
			const auto deletedCount = storage.count<DeletedMessage>(
				where(column<DeletedMessage>(&DeletedMessage::userId) == userId));
			if (editedCount + deletedCount > maxRows) {
				return std::nullopt;
			}
			return result;
		}
		result.deleted = storage.get_all<DeletedMessage>(
			where(column<DeletedMessage>(&DeletedMessage::userId) == userId),
			order_by(column<DeletedMessage>(&DeletedMessage::fakeId)),
			limit(remaining));
		const auto editedCount = storage.count<EditedMessage>(
			where(column<EditedMessage>(&EditedMessage::userId) == userId));
		const auto deletedCount = storage.count<DeletedMessage>(
			where(column<DeletedMessage>(&DeletedMessage::userId) == userId));
		if (editedCount + deletedCount > maxRows) {
			return std::nullopt;
		}
		return result;
	} catch (const std::exception &ex) {
		LOG(("Failed to snapshot archived messages: %1").arg(ex.what()));
		return std::nullopt;
	}
}

ArchiveImportCounts importArchiveSnapshot(
		ID userId,
		const ArchiveBackupSnapshot &snapshot) {
	auto result = ArchiveImportCounts();
	if (snapshot.edited.size() + snapshot.deleted.size() > 100000) {
		return result;
	}
	std::lock_guard lock(databaseMutex);
	const auto database = ArchiveForUser(userId);
	if (!database) {
		return {};
	}
	auto &storage = *database;
	try {
		storage.begin_transaction();
		auto editedRows = storage.get_all<EditedMessage>(
			where(column<EditedMessage>(&EditedMessage::userId) == userId));
		auto deletedRows = storage.get_all<DeletedMessage>(
			where(column<DeletedMessage>(&DeletedMessage::userId) == userId));
		for (auto row : snapshot.edited) {
			if (row.userId != userId || row.text.size() > 1024 * 1024
				|| row.peerType < 0 || row.peerType > 3) {
				storage.rollback();
				return {};
			}
			const auto duplicate = std::ranges::any_of(editedRows, [&](const auto &old) {
				return old.dialogId == row.dialogId
					&& old.topicId == row.topicId
					&& old.messageId == row.messageId
					&& old.editDate == row.editDate
					&& old.text == row.text;
			});
			if (duplicate) {
				++result.editedSkipped;
				continue;
			}
			row.fakeId = 0;
			storage.insert(row);
			editedRows.push_back(row);
			++result.editedAdded;
		}
		for (auto row : snapshot.deleted) {
			if (row.userId != userId || row.text.size() > 1024 * 1024
				|| row.peerType < 0 || row.peerType > 3) {
				storage.rollback();
				return {};
			}
			const auto duplicate = std::ranges::any_of(deletedRows, [&](const auto &old) {
				return old.dialogId == row.dialogId
					&& old.topicId == row.topicId
					&& old.messageId == row.messageId
					&& old.date == row.date
					&& old.text == row.text;
			});
			if (duplicate) {
				++result.deletedSkipped;
				continue;
			}
			row.fakeId = 0;
			storage.insert(row);
			deletedRows.push_back(row);
			++result.deletedAdded;
		}
		storage.commit();
		result.committed = true;
	} catch (const std::exception &ex) {
		storage.rollback();
		LOG(("Failed to import archived messages: %1").arg(ex.what()));
	}
	return result;
}

template<typename T>
std::vector<T> getAllT() {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return {};
	}
	auto &storage = LegacyStorage();
	try {
		return storage.get_all<T>();
	} catch (std::exception &ex) {
		LOG(("Failed to get all: %1").arg(ex.what()));
		return {};
	}
}

std::vector<RegexFilter> getAllRegexFilters() {
	return getAllT<RegexFilter>();
}

std::vector<RegexFilterGlobalExclusion> getAllFiltersExclusions() {
	return getAllT<RegexFilterGlobalExclusion>();
}

std::vector<RegexFilter> getExcludedByDialogId(ID dialogId) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return {};
	}
	auto &storage = LegacyStorage();
	try {
		return storage.get_all<RegexFilter>(
			where(in(&RegexFilter::id,
					 storage.select(columns(&RegexFilterGlobalExclusion::filterId),
									where(is_equal(&RegexFilterGlobalExclusion::dialogId, dialogId))
					 )
			))
		);
	} catch (std::exception &ex) {
		LOG(("Failed to get excluded by dialog id: %1").arg(ex.what()));
		return {};
	}
}

int getCount() {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return {};
	}
	auto &storage = LegacyStorage();
	try {
		return storage.count<RegexFilter>();
	} catch (std::exception &ex) {
		LOG(("Failed to get count: %1").arg(ex.what()));
		return 0;
	}
}

RegexFilter getById(std::vector<char> id) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return {};
	}
	auto &storage = LegacyStorage();
	try {
		return storage.get<RegexFilter>(
			where(column<RegexFilter>(&RegexFilter::id) == std::move(id))
		);
	} catch (std::exception &ex) {
		LOG(("Failed to get filters by id: %1").arg(ex.what()));
		return {};
	}
}

std::vector<RegexFilter> getShared() {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return {};
	}
	auto &storage = LegacyStorage();
	try {
		return storage.get_all<RegexFilter>(
			where(is_null(column<RegexFilter>(&RegexFilter::dialogId)))
		);
	} catch (std::exception &ex) {
		LOG(("Failed to get shared filters: %1").arg(ex.what()));
		return {};
	}
}

std::vector<RegexFilter> getByDialogId(ID dialogId) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return {};
	}
	auto &storage = LegacyStorage();
	try {
		return storage.get_all<RegexFilter>(
			where(column<RegexFilter>(&RegexFilter::dialogId) == dialogId)
		);
	} catch (std::exception &ex) {
		LOG(("Failed to get filters by dialog id: %1").arg(ex.what()));
		return {};
	}
}

void addRegexFilter(const RegexFilter &filter) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return;
	}
	auto &storage = LegacyStorage();
	try {
		storage.begin_transaction();
		storage.replace(filter); // we're using replace as we set std::vector<char> as primary key
		storage.commit();
	} catch (std::exception &ex) {
		try {
			storage.rollback();
		} catch (...) {
		}
		LOG(("Failed to save regex filter for some reason: %1").arg(ex.what()));
	}
}

void addRegexExclusion(const RegexFilterGlobalExclusion &exclusion) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return;
	}
	auto &storage = LegacyStorage();
	try {
		storage.begin_transaction();
		storage.insert(exclusion);
		storage.commit();
	} catch (std::exception &ex) {
		try {
			storage.rollback();
		} catch (...) {
		}
		LOG(("Failed to save regex filter exclusion for some reason: %1").arg(ex.what()));
	}
}

void updateRegexFilter(const RegexFilter &filter) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return;
	}
	auto &storage = LegacyStorage();
	try {
		storage.update_all(
			set(
				c(&RegexFilter::text) = filter.text,
				c(&RegexFilter::enabled) = filter.enabled,
				c(&RegexFilter::reversed) = filter.reversed,
				c(&RegexFilter::caseInsensitive) = filter.caseInsensitive,
				c(&RegexFilter::dialogId) = filter.dialogId
			),
			where(c(&RegexFilter::id) == filter.id)
		);
	} catch (std::exception &ex) {
		LOG(("Failed to update regex filter for some reason: %1").arg(ex.what()));
	}
}

void deleteFilter(const std::vector<char> &id) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return;
	}
	auto &storage = LegacyStorage();
	try {
		storage.remove_all<RegexFilter>(
			where(column<RegexFilter>(&RegexFilter::id) == id)
		);
	} catch (std::exception &ex) {
		LOG(("Failed to delete regex filter for some reason: %1").arg(ex.what()));
	}
}

void deleteExclusionsByFilterId(const std::vector<char> &id) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return;
	}
	auto &storage = LegacyStorage();
	try {
		storage.remove_all<RegexFilterGlobalExclusion>(
			where(column<RegexFilterGlobalExclusion>(&RegexFilterGlobalExclusion::filterId) == id)
		);
	} catch (std::exception &ex) {
		LOG(("Failed to delete regex filter exclusion by filter id for some reason: %1").arg(ex.what()));
	}
}

void deleteExclusion(ID dialogId, std::vector<char> filterId) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return;
	}
	auto &storage = LegacyStorage();
	try {
		storage.remove_all<RegexFilterGlobalExclusion>(
			where(column<RegexFilterGlobalExclusion>(&RegexFilterGlobalExclusion::filterId) == filterId and
				column<RegexFilterGlobalExclusion>(&RegexFilterGlobalExclusion::dialogId) == dialogId
			)
		);
	} catch (std::exception &ex) {
		LOG(("Failed to delete regex filter exclusion for some reason: %1").arg(ex.what()));
	}
}

void deleteAllFilters() {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return;
	}
	auto &storage = LegacyStorage();
	try {
		storage.remove_all<RegexFilter>();
	} catch (std::exception &ex) {
		LOG(("Failed to delete all regex filter for some reason: %1").arg(ex.what()));
	}
}

void deleteAllExclusions() {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return;
	}
	auto &storage = LegacyStorage();
	try {
		storage.remove_all<RegexFilterGlobalExclusion>();
	} catch (std::exception &ex) {
		LOG(("Failed to delete all regex filter exclusions for some reason: %1").arg(ex.what()));
	}
}

bool replaceAllRegexFilters(
		const std::vector<RegexFilter> &filters,
		const std::vector<RegexFilterGlobalExclusion> &exclusions) {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return {};
	}
	auto &storage = LegacyStorage();
	try {
		storage.begin_transaction();
		storage.remove_all<RegexFilterGlobalExclusion>();
		storage.remove_all<RegexFilter>();
		for (const auto &filter : filters) {
			storage.replace(filter);
		}
		for (const auto &exclusion : exclusions) {
			storage.insert(exclusion);
		}
		storage.commit();
		return true;
	} catch (const std::exception &ex) {
		try {
			storage.rollback();
		} catch (...) {
		}
		LOG(("Failed to replace regex filters: %1").arg(ex.what()));
		return false;
	}
}

bool hasFilters() {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return {};
	}
	auto &storage = LegacyStorage();
	try {
		return !storage.select(
			columns(column<RegexFilter>(&RegexFilter::id)),
			limit(1)
		).empty();
	} catch (std::exception &ex) {
		LOG(("Failed to check if there's any filters: %1").arg(ex.what()));
		return false;
	}
}

bool hasPerDialogFilters() {
	std::lock_guard lock(databaseMutex);
	if (archiveRuntime.scoped) {
		return {};
	}
	auto &storage = LegacyStorage();
	try {
		return
			!storage.select(
				columns(column<RegexFilter>(&RegexFilter::id)),
				where(is_not_null(column<RegexFilter>(&RegexFilter::dialogId))),
				limit(1)
			).empty() ||
			!storage.select(
				columns(column<RegexFilterGlobalExclusion>(&RegexFilterGlobalExclusion::fakeId)),
				limit(1)
			).empty();
	} catch (std::exception &ex) {
		LOG(("Failed to check if there's any filters: %1").arg(ex.what()));
		return false;
	}
}

}
