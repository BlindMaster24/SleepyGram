// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#pragma once

#include "ayu/data/entities.h"
#include "ayu/data/ayu_database.h"

#include <optional>

namespace Main {
class Session;
} // namespace Main

namespace AyuMessages {

enum class DeletedMessagePolicy {
	Inherit = -1,
	Off = 0,
	On = 1,
};

using ArchiveSearchType = AyuDatabase::ArchiveSearchType;
using ArchiveSearchCursor = AyuDatabase::ArchiveSearchCursor;
using ArchiveSearchResult = AyuDatabase::ArchiveSearchResult;

std::vector<ArchiveSearchResult> searchArchive(
	ID userId,
	const QString &searchQuery,
	ArchiveSearchType type,
	int dateFrom,
	int dateTo,
	std::optional<ArchiveSearchCursor> cursor,
	int pageLimit);

void addEditedMessage(not_null<HistoryItem *> item);
std::vector<AyuMessageBase> getEditedMessages(not_null<HistoryItem*> item, ID minId, ID maxId, int totalLimit);
std::vector<AyuMessageBase> getEditedMessages(not_null<PeerData*> peer, ID topicId, ID minId, ID maxId, int totalLimit, const QString &searchQuery = QString());
std::vector<AyuMessageBase> getEditedMessageRevisions(not_null<PeerData*> peer, ID messageId, ID topicId, ID minId, ID maxId, int totalLimit);
bool hasRevisions(not_null<HistoryItem*> item);

void addDeletedMessage(not_null<HistoryItem*> item);
[[nodiscard]] DeletedMessagePolicy deletedMessagePolicy(not_null<PeerData*> peer);
void setDeletedMessagePolicy(not_null<PeerData*> peer, DeletedMessagePolicy policy);
std::vector<AyuMessageBase> getDeletedMessages(not_null<PeerData*> peer, ID topicId, ID minId, ID maxId, int totalLimit, const QString &searchQuery = QString());
bool hasDeletedMessages(not_null<PeerData*> peer, ID topicId);
void removeDeletedMessage(not_null<HistoryItem*> item);
void clearDeletedMessages(not_null<PeerData*> peer, ID topicId);

}
