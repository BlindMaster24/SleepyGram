// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026
#include "ayu/features/filters/filters_cache_controller.h"

#include "ayu/data/ayu_database.h"
#include "ayu/features/filters/filters_controller.h"
#include "data/data_groups.h"
#include "data/data_peer.h"
#include "data/data_session.h"
#include "history/history.h"
#include "history/history_item.h"
#include "main/main_session.h"
#include "rpl/event_stream.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <unordered_set>

namespace FiltersCacheController {

std::mutex rebuildMutex;
std::mutex cacheMutex;
std::mutex filteredMessagesMutex;

struct DialogScope {
	uint64 accountId = 0;
	uint64 peerId = 0;

	friend bool operator==(const DialogScope &, const DialogScope &) = default;
};

struct DialogScopeHasher {
	std::size_t operator()(const DialogScope &scope) const {
		const auto accountHash = std::hash<uint64>()(scope.accountId);
		const auto peerHash = std::hash<uint64>()(scope.peerId);
		return accountHash ^ (peerHash + 0x9e3779b9 + (accountHash << 6) + (accountHash >> 2));
	}
};

DialogScope ScopeFor(not_null<PeerData*> peer) {
	return {
		peer->session().userId().bare,
		peer->id.value
	};
}

DialogScope ScopeFor(not_null<HistoryItem*> item) {
	return ScopeFor(item->history()->peer);
}

rpl::event_stream<> filtersUpdateStream;

void fireUpdate() {
	filtersUpdateStream.fire({});
}

rpl::producer<> updates() {
	return filtersUpdateStream.events();
}

std::shared_ptr<const Cache> cache;

std::unordered_map<DialogScope, std::unordered_map<int64, bool>, DialogScopeHasher> filteredMessages;
std::unordered_map<DialogScope, std::unordered_set<int64>, DialogScopeHasher> filteredUnreadCandidates;
std::unordered_set<DialogScope, DialogScopeHasher> dialogsWithHiddenBlockedMessages; // purely for show / hide filtered messages

std::shared_ptr<const Cache> buildCache() {
	const auto filters = AyuDatabase::getAllRegexFilters();
	const auto exclusions = AyuDatabase::getAllFiltersExclusions();

	std::vector<HashablePattern> shared;
	std::unordered_map<ID, std::vector<ReversiblePattern>> byDialogId;

	for (const auto &filter : filters) {
		if (!filter.enabled || filter.text.empty()) {
			continue;
		}

		int flags = UREGEX_MULTILINE;
		if (filter.caseInsensitive) flags |= UREGEX_CASE_INSENSITIVE;

		auto status = U_ZERO_ERROR;
		auto pattern = icu::RegexPattern::compile(icu::UnicodeString::fromUTF8(filter.text), flags, status);

		if (!pattern) {
			continue;
		}

		if (filter.dialogId.has_value()) {
			byDialogId[filter.dialogId.value()].push_back({
				std::shared_ptr<icu::RegexPattern>(pattern),
				filter.reversed,
				QString::fromStdString(filter.text),
			});
		} else {
			shared.push_back({
				filter.id,
				{
					std::shared_ptr<icu::RegexPattern>(pattern),
					filter.reversed,
					QString::fromStdString(filter.text),
				},
			});
		}
	}

	auto exclByDialogId = buildExclusions(exclusions, shared);
	auto result = std::make_shared<Cache>();
	result->sharedPatterns = std::move(shared);
	result->patternsByDialogId = std::move(byDialogId);
	result->exclusionsByDialogId = std::move(exclByDialogId);

	return result;
}

void rebuildCache() {
	std::lock_guard rebuildLock(rebuildMutex);
	auto next = buildCache();
	{
		std::lock_guard cacheLock(cacheMutex);
		std::lock_guard filteredLock(filteredMessagesMutex);
		cache = std::move(next);
		filteredMessages.clear();
		filteredUnreadCandidates.clear();
		dialogsWithHiddenBlockedMessages.clear();
	}
}

std::unordered_map<long long, std::unordered_set<HashablePattern, PatternHasher>> buildExclusions(
	const std::vector<RegexFilterGlobalExclusion> &exclusions,
	const std::vector<HashablePattern> &shared) {
	std::unordered_map<long long, std::unordered_set<HashablePattern, PatternHasher>> exclusionsByDialogId;

	for (const auto &exclusion : exclusions) {
		auto &exclusionSet = exclusionsByDialogId[exclusion.dialogId];

		for (const auto &filter : shared) {
			if (filter.id == exclusion.filterId) {
				exclusionSet.insert(filter);
				break;
			}
		}
	}
	return exclusionsByDialogId;
}

std::shared_ptr<const Cache> snapshot() {
	{
		std::lock_guard lock(cacheMutex);
		if (cache) {
			return cache;
		}
	}

	std::lock_guard rebuildLock(rebuildMutex);
	{
		std::lock_guard lock(cacheMutex);
		if (cache) {
			return cache;
		}
	}

	auto next = buildCache();
	std::lock_guard lock(cacheMutex);
	if (!cache) {
		cache = std::move(next);
	}
	return cache;
}

std::optional<bool> isFiltered(not_null<HistoryItem*> item) {
	std::lock_guard lock(filteredMessagesMutex);
	auto dialogIt = filteredMessages.find(ScopeFor(item));

	if (dialogIt == filteredMessages.end()) {
		return std::nullopt;
	}

	const auto it = dialogIt->second.find(item->id.bare);
	if (it == dialogIt->second.end()) {
		return std::nullopt;
	}

	return it->second;
}

bool hasFilteredMessages(not_null<PeerData*> peer) {
	std::lock_guard lock(filteredMessagesMutex);
	const auto scope = ScopeFor(peer);
	if (dialogsWithHiddenBlockedMessages.contains(scope)) {
		return true;
	}
	const auto dialogIt = filteredUnreadCandidates.find(scope);
	return (dialogIt != filteredUnreadCandidates.end())
		&& !dialogIt->second.empty();
}

void putHiddenBlockedMessage(not_null<HistoryItem*> item) {
	std::lock_guard lock(filteredMessagesMutex);
	dialogsWithHiddenBlockedMessages.insert(ScopeFor(item));
}

void putFiltered(
		not_null<HistoryItem*> item,
		const Data::Group *group,
		bool res,
		const std::shared_ptr<const Cache> &matchedCache) {
	std::lock_guard cacheLock(cacheMutex);
	if (cache != matchedCache) {
		return;
	}

	std::lock_guard filteredLock(filteredMessagesMutex);
	const auto scope = ScopeFor(item);
	filteredMessages[scope][item->id.bare] = res;
	if (res) {
		filteredUnreadCandidates[scope].insert(item->id.bare);
	} else if (const auto i = filteredUnreadCandidates.find(scope);
		i != filteredUnreadCandidates.end()) {
		i->second.erase(item->id.bare);
	}
	if (group && res) {
		for (const auto& groupItem : group->items) {
			filteredMessages[scope][groupItem->id.bare] = true;
			filteredUnreadCandidates[scope].insert(groupItem->id.bare);
		}
	}
}

void invalidateSingle(not_null<HistoryItem*> item) {
	const auto scope = ScopeFor(item);
	const auto dialogIt = filteredMessages.find(scope);

	if (dialogIt == filteredMessages.end()) {
		return;
	}

	const auto it = dialogIt->second.find(item->id.bare);
	if (it == dialogIt->second.end()) {
		return;
	}

	dialogIt->second.erase(it);
	if (const auto candidates = filteredUnreadCandidates.find(scope);
		candidates != filteredUnreadCandidates.end()) {
		candidates->second.erase(item->id.bare);
	}
}

void invalidate(not_null<HistoryItem*> item) {
	std::lock_guard lock(filteredMessagesMutex);
	if (const auto group = item->history()->owner().groups().find(item)) {
		for (const auto& groupItem : group->items) {
			invalidateSingle(groupItem);
		}
	} else {
		invalidateSingle(item);
	}
}

void clearAccount(uint64 accountId) {
	std::lock_guard lock(filteredMessagesMutex);
	const auto clearMaps = [=](auto &cache) {
		for (auto i = cache.begin(); i != cache.end();) {
			if (i->first.accountId == accountId) {
				i = cache.erase(i);
			} else {
				++i;
			}
		}
	};
	clearMaps(filteredMessages);
	clearMaps(filteredUnreadCandidates);
	for (auto i = dialogsWithHiddenBlockedMessages.begin();
		i != dialogsWithHiddenBlockedMessages.end();) {
		if (i->accountId == accountId) {
			i = dialogsWithHiddenBlockedMessages.erase(i);
		} else {
			++i;
		}
	}
}

int countKnownFilteredUnread(
		not_null<const History*> history,
		Fn<bool(not_null<const HistoryItem*>)> isUnread) {
	constexpr auto kMaxCandidatesPerBadge = std::size_t(256);
	const auto peer = history->peer;
	if (!FiltersController::isEnabled(peer)
		|| FiltersController::filteredMessagesShown(peer).value_or(false)) {
		return 0;
	}
	auto filteredIds = std::vector<MsgId>();
	{
		std::lock_guard lock(filteredMessagesMutex);
		const auto dialog = filteredUnreadCandidates.find(ScopeFor(peer));
		if (dialog == filteredUnreadCandidates.end()) {
			return 0;
		}
		filteredIds.reserve(std::min(
			dialog->second.size(),
			kMaxCandidatesPerBadge));
		for (const auto id : dialog->second) {
			if (filteredIds.size() == kMaxCandidatesPerBadge) {
				break;
			}
			filteredIds.push_back(MsgId(id));
		}
	}
	auto result = 0;
	for (const auto id : filteredIds) {
		if (const auto item = history->owner().message(peer->id, id);
			item && isUnread(item)) {
			++result;
		}
	}
	return result;
}

}
