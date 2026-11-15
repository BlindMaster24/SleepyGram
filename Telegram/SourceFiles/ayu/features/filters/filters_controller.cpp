// This is the source code of AyuGram for Desktop.
//
// We do not and cannot prevent the use of our code,
// but be respectful and credit the original author.
//
// Copyright @Radolyn, 2026

#include "ayu/features/filters/filters_controller.h"

#include "ayu/ayu_settings.h"
#include "ayu/features/filters/filters_cache_controller.h"
#include "ayu/features/filters/filters_utils.h"
#include "ayu/utils/telegram_helpers.h"
#include "data/data_peer.h"
#include "data/data_peer_id.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_components.h"
#include "unicode/regex.h"

#include <memory>
#include <unordered_set>

namespace FiltersController {

std::unordered_set<long long> showingFilteredMessages;

std::optional<HiddenReason> matchingFilter(
	const QString &str,
	long long dialogId,
	const std::shared_ptr<const FiltersCacheController::Cache> &cache);

std::optional<bool> isFiltered(
		const QString &str,
		long long dialogId,
		const std::shared_ptr<const FiltersCacheController::Cache> &cache) {
	return matchingFilter(str, dialogId, cache).has_value();
}

std::optional<HiddenReason> matchingFilter(
		const QString &str,
		long long dialogId,
		const std::shared_ptr<const FiltersCacheController::Cache> &cache) {
	if (str.isEmpty()) {
		return std::nullopt;
	}
	const auto icuStr = icu::UnicodeString(
		reinterpret_cast<const UChar*>(str.constData()),
		str.length());
	const auto matches = [&](const ReversiblePattern &pattern) {
		auto status = U_ZERO_ERROR;
		const auto matcher = std::unique_ptr<icu::RegexMatcher>(
			pattern.pattern->matcher(icuStr, status));
		if (U_FAILURE(status) || !matcher) {
			LOG(("FILTER FAILED: %1").arg(u_errorName(status)));
			return false;
		}
		const auto found = matcher->find();
		return pattern.reversed ? !found : bool(found);
	};
	if (const auto i = cache->patternsByDialogId.find(dialogId);
		i != cache->patternsByDialogId.end()) {
		for (const auto &pattern : i->second) {
			if (matches(pattern)) {
				return HiddenReason{
					.kind = HiddenReason::Kind::DialogFilter,
					.rule = pattern.text,
				};
			}
		}
	}
	const auto exclusions = cache->exclusionsByDialogId.find(dialogId);
	for (const auto &pattern : cache->sharedPatterns) {
		if (exclusions != cache->exclusionsByDialogId.end()
			&& exclusions->second.contains(pattern)) {
			continue;
		}
		if (matches(pattern.pattern)) {
			return HiddenReason{
				.kind = HiddenReason::Kind::SharedFilter,
				.rule = pattern.pattern.text,
			};
		}
	}
	return std::nullopt;
}

std::optional<HiddenReason> localBanReason(not_null<HistoryItem*> item) {
	const auto &settings = AyuSettings::getInstance();
	const auto shadowBanned = [&](PeerData *peer) {
		return peer
			&& (peer->isUser() || peer->isBroadcast())
			&& settings.isShadowBanned(getDialogIdFromPeer(peer));
	};
	const auto blockedUser = [&](PeerData *peer) {
		return peer && peer->isUser() && peer->asUser()->isBlocked();
	};
	if (item->from() != item->history()->peer) {
		if (shadowBanned(item->from())
			&& item->from()->id != item->history()->peer->id) {
			return HiddenReason{ .kind = HiddenReason::Kind::ShadowBan };
		}
		if (blockedUser(item->from())
			&& item->from()->id != item->history()->peer->id
			&& settings.hideFromBlocked()) {
			return HiddenReason{ .kind = HiddenReason::Kind::LocalBlock };
		}
	}
	if (const auto forwarded = item->Get<HistoryMessageForwarded>()) {
		if (const auto peer = forwarded->originalSender) {
			if (shadowBanned(peer)) {
				return HiddenReason{ .kind = HiddenReason::Kind::ShadowBan };
			}
			if (blockedUser(peer) && settings.hideFromBlocked()) {
				return HiddenReason{ .kind = HiddenReason::Kind::LocalBlock };
			}
		}
	}
	if (const auto bot = item->viaBot()) {
		if (shadowBanned(bot)) {
			return HiddenReason{ .kind = HiddenReason::Kind::ShadowBan };
		}
		if (blockedUser(bot) && settings.hideFromBlocked()) {
			return HiddenReason{ .kind = HiddenReason::Kind::LocalBlock };
		}
	}
	return std::nullopt;
}

bool isEnabled(not_null<PeerData*> peer) {
	const auto &settings = AyuSettings::getInstance();
	return settings.filtersEnabled() && (settings.filtersEnabledInChats() || peer->isBroadcast());
}

bool isBlocked(const not_null<HistoryItem*> item) {
	return AyuSettings::getInstance().filtersEnabled()
		&& localBanReason(item).has_value();
}

bool isBlocked(const not_null<PeerData*> peer) {
	const auto &settings = AyuSettings::getInstance();
	return settings.filtersEnabled() &&
	(
		(peer->isUser() && peer->asUser()->isBlocked() && settings.hideFromBlocked()) ||
		((peer->isUser() || peer->isBroadcast()) && settings.isShadowBanned(getDialogIdFromPeer(peer)))
	);
}

bool filtered(const not_null<HistoryItem*> item) {
	if (showingFilteredMessages.contains(item->history()->peer->id.value)) {
		return false;
	}

	const auto &settings = AyuSettings::getInstance();
	if (!settings.filtersEnabled()) {
		return false;
	}

	if (item->out()) {
		return false;
	}

	if (localBanReason(item)) {
		FiltersCacheController::putHiddenBlockedMessage(item);
		return true;
	}

	if (!isEnabled(item->history()->peer)) return false;

	const auto cached = FiltersCacheController::isFiltered(item);
	if (cached.has_value()) {
		return cached.value();
	}
	const auto group = item->history()->owner().groups().find(item);
	const auto cache = FiltersCacheController::snapshot();
	const auto res = isFiltered(
		FilterUtils::extractAllText(item, group),
		getDialogIdFromPeer(item->history()->peer),
		cache);

	// sometimes item has empty text.
	// so we cache result only if
	// processed item is filterable
	if (res.has_value()) {
		FiltersCacheController::putFiltered(item, group, res.value(), cache);
		return res.value();
	}
	return false;
}

std::optional<HiddenReason> whyHidden(not_null<HistoryItem*> item) {
	if (item->out()) {
		return std::nullopt;
	}
	const auto &settings = AyuSettings::getInstance();
	if (!settings.filtersEnabled()) {
		return std::nullopt;
	}
	if (const auto reason = localBanReason(item)) {
		return reason;
	}
	if (!isEnabled(item->history()->peer)) {
		return std::nullopt;
	}
	const auto group = item->history()->owner().groups().find(item);
	return matchingFilter(
		FilterUtils::extractAllText(item, group),
		getDialogIdFromPeer(item->history()->peer),
		FiltersCacheController::snapshot());
}

std::optional<bool> filteredMessagesShown(not_null<PeerData*> peer) {
	if (!showingFilteredMessages.contains(peer->id.value)
		&& !FiltersCacheController::hasFilteredMessages(peer)) {
		return std::nullopt;
	}
	return showingFilteredMessages.contains(peer->id.value);
}

void toggleFilteredMessagesShown(not_null<PeerData*> peer) {
	if (showingFilteredMessages.contains(peer->id.value)) {
		showingFilteredMessages.erase(peer->id.value);
	} else {
		showingFilteredMessages.insert(peer->id.value);
	}
	FiltersCacheController::fireUpdate();
}

void invalidate(not_null<HistoryItem*> item) {
	const auto &settings = AyuSettings::getInstance();
	if (!settings.filtersEnabled()) {
		return;
	}

	FiltersCacheController::invalidate(item);
}

}
