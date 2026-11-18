// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#pragma once

#include "ayu/data/archive_migration.h"
#include "ayu/data/entities.h"

#include <cstdint>
#include <functional>
#include <optional>

class SchemaVersion
{
public:
	int id;
	int version;
};

namespace AyuDatabase {

enum class ArchiveSearchType : uint8_t {
	All,
	Edited,
	Deleted,
};

struct ArchiveSearchCursor {
	int date = 0;
	ArchiveSearchType type = ArchiveSearchType::All;
	ID rowId = 0;
};

struct ArchiveSearchResult {
	ArchiveSearchType type = ArchiveSearchType::Edited;
	int date = 0;
	ID rowId = 0;
	AyuMessageBase message;
};

struct ArchiveBackupCounts {
	int edited = 0;
	int deleted = 0;
};

struct ArchiveBackupSnapshot {
	std::vector<EditedMessage> edited;
	std::vector<DeletedMessage> deleted;
};

struct ArchiveImportCounts {
	bool committed = false;
	int editedAdded = 0;
	int editedSkipped = 0;
	int deletedAdded = 0;
	int deletedSkipped = 0;
};

void initialize();

[[nodiscard]] Ayu::ArchivePartitionResult StageLegacyArchivePartitions(
	const std::filesystem::path &dataDirectory,
	std::span<const Ayu::LegacyArchiveFileTarget> targets);

void addEditedMessage(const EditedMessage &message);
std::vector<EditedMessage> getEditedMessages(ID userId, ID dialogId, ID messageId, ID minId, ID maxId, int totalLimit);
std::vector<EditedMessage> getEditedMessages(ID userId, ID dialogId, ID topicId, ID minId, ID maxId, int totalLimit, const std::string &searchQuery);
std::vector<EditedMessage> getEditedMessageRevisions(ID userId, ID dialogId, ID messageId, ID topicId, ID minId, ID maxId, int totalLimit);
bool hasRevisions(ID userId, ID dialogId, ID messageId);

void addDeletedMessage(const DeletedMessage &message);
std::vector<DeletedMessage> getDeletedMessages(ID userId, ID dialogId, ID topicId, ID minId, ID maxId, int totalLimit, const std::string &searchQuery = "");
bool hasDeletedMessages(ID userId, ID dialogId, ID topicId);
void removeDeletedMessage(ID userId, ID dialogId, ID messageId);
void clearDeletedMessages(ID userId, ID dialogId, ID topicId);

std::vector<ArchiveSearchResult> searchArchive(
	ID userId,
	const std::string &searchQuery,
	ArchiveSearchType type,
	int dateFrom,
	int dateTo,
	std::optional<ArchiveSearchCursor> cursor,
	int pageLimit);

ArchiveBackupCounts archiveBackupCounts(ID userId);
std::optional<ArchiveBackupSnapshot> archiveBackupSnapshot(
	ID userId,
	int maxRows);
ArchiveImportCounts importArchiveSnapshot(
	ID userId,
	const ArchiveBackupSnapshot &snapshot);

std::vector<RegexFilter> getAllRegexFilters();
RegexFilter getById(std::vector<char> id);
std::vector<RegexFilter> getShared();
std::vector<RegexFilter> getByDialogId(ID dialogId);
std::vector<RegexFilterGlobalExclusion> getAllFiltersExclusions();
std::vector<RegexFilter> getExcludedByDialogId(ID dialogId);

int getCount();


void addRegexFilter(const RegexFilter &filter);
void addRegexExclusion(const RegexFilterGlobalExclusion &exclusion);

void updateRegexFilter(const RegexFilter &filter);

void deleteFilter(const std::vector<char> &id);
void deleteExclusionsByFilterId(const std::vector<char> &id);
void deleteExclusion(ID dialogId, std::vector<char> filterId);

void deleteAllFilters();
void deleteAllExclusions();
bool replaceAllRegexFilters(
	const std::vector<RegexFilter> &filters,
	const std::vector<RegexFilterGlobalExclusion> &exclusions);

bool hasFilters();
bool hasPerDialogFilters();

void moveCurrentDatabase();

}
