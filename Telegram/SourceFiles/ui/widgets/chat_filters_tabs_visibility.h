/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "main/main_session.h"
#include "data/data_chat_filters.h"
#include "data/data_session.h"
#include "data/data_types.h"
#include "storage/storage_account.h"

#include <string>
#include <utility>
#include <vector>

namespace Ui {

enum class ChatFilterTabVisibility : uchar {
	Show,
	ShowWithoutBadge,
	Hidden,
};

namespace details {

inline auto &ChatFilterTabVisibilityChanges() {
	static auto changes = rpl::event_stream<not_null<Main::Session*>>();
	return changes;
}

inline auto ChatFilterTabHiddenPrefKey(FilterId id) {
	return "ayu.hiddenChatFolder." + std::to_string(id);
}

inline auto ChatFilterTabVisibilityPrefKey(FilterId id) {
	return "ayu.chatFolderVisibility." + std::to_string(id);
}

} // namespace details

[[nodiscard]] inline ChatFilterTabVisibility GetChatFilterTabVisibility(
		not_null<Main::Session*> session,
		FilterId id) {
	const auto raw = session->local().readPref<QString>(
		details::ChatFilterTabVisibilityPrefKey(id));
	if (raw == u"no_badge"_q) {
		return ChatFilterTabVisibility::ShowWithoutBadge;
	} else if (raw == u"hidden"_q && id) {
		return ChatFilterTabVisibility::Hidden;
	} else if (raw == u"show"_q) {
		return ChatFilterTabVisibility::Show;
	}
	if (id && session->local().readPref<bool>(
			details::ChatFilterTabHiddenPrefKey(id))) {
		return ChatFilterTabVisibility::Hidden;
	}
	return ChatFilterTabVisibility::Show;
}

inline void SetChatFilterTabVisibility(
		not_null<Main::Session*> session,
		FilterId id,
		ChatFilterTabVisibility visibility) {
	if (!id && visibility == ChatFilterTabVisibility::Hidden) {
		visibility = ChatFilterTabVisibility::Show;
	}
	if (GetChatFilterTabVisibility(session, id) == visibility) {
		return;
	}
	const auto key = details::ChatFilterTabVisibilityPrefKey(id);
	const auto legacyKey = details::ChatFilterTabHiddenPrefKey(id);
	switch (visibility) {
	case ChatFilterTabVisibility::Show:
		session->local().clearPref(key);
		session->local().clearPref(legacyKey);
		break;
	case ChatFilterTabVisibility::ShowWithoutBadge:
		session->local().writePref<QString>(key, u"no_badge"_q);
		session->local().clearPref(legacyKey);
		break;
	case ChatFilterTabVisibility::Hidden:
		session->local().writePref<QString>(key, u"hidden"_q);
		session->local().clearPref(legacyKey);
		break;
	}
	details::ChatFilterTabVisibilityChanges().fire(std::move(session));
}

inline void ClearChatFilterTabVisibility(
		not_null<Main::Session*> session,
		FilterId id) {
	if (!id) {
		return;
	}
	session->local().clearPref(details::ChatFilterTabVisibilityPrefKey(id));
	session->local().clearPref(details::ChatFilterTabHiddenPrefKey(id));
}

[[nodiscard]] inline bool ChatFilterTabHidden(
		not_null<Main::Session*> session,
		FilterId id) {
	return id
		&& (GetChatFilterTabVisibility(session, id)
			== ChatFilterTabVisibility::Hidden);
}

[[nodiscard]] inline bool ChatFilterTabBadgeHidden(
		not_null<Main::Session*> session,
		FilterId id) {
	return GetChatFilterTabVisibility(session, id)
		== ChatFilterTabVisibility::ShowWithoutBadge;
}

inline void SetChatFilterTabHidden(
		not_null<Main::Session*> session,
		FilterId id,
		bool hidden) {
	if (!id) {
		return;
	}
	SetChatFilterTabVisibility(
		session,
		id,
		hidden
			? ChatFilterTabVisibility::Hidden
			: ChatFilterTabVisibility::Show);
}

[[nodiscard]] inline rpl::producer<not_null<Main::Session*>>
ChatFilterTabVisibilityChanges() {
	return details::ChatFilterTabVisibilityChanges().events();
}

[[nodiscard]] inline std::vector<FilterId> VisibleChatFilterTabIds(
		not_null<Main::Session*> session) {
	const auto &filters = session->data().chatsFilters();
	const auto &list = filters.list();
	auto result = std::vector<FilterId>();
	result.reserve(list.size() + 1);
	for (const auto &filter : list) {
		if (!filter.id() || !ChatFilterTabHidden(session, filter.id())) {
			result.push_back(filter.id());
		}
	}
	if (filters.mentionsFolderEnabled()
		&& !ChatFilterTabHidden(session, Data::kMentionsFilterId)) {
		if (result.empty()) {
			result.push_back(FilterId(0));
		}
		result.push_back(Data::kMentionsFilterId);
	}
	return result;
}

} // namespace Ui
