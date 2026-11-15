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
namespace details {

inline auto &ChatFilterTabVisibilityChanges() {
	static auto changes = rpl::event_stream<not_null<Main::Session*>>();
	return changes;
}

inline auto ChatFilterTabVisibilityPrefKey(FilterId id) {
	return "ayu.hiddenChatFolder." + std::to_string(id);
}

} // namespace details

[[nodiscard]] inline bool ChatFilterTabHidden(
		not_null<Main::Session*> session,
		FilterId id) {
	return id && session->local().readPref<bool>(
		details::ChatFilterTabVisibilityPrefKey(id));
}

inline void SetChatFilterTabHidden(
		not_null<Main::Session*> session,
		FilterId id,
		bool hidden) {
	if (!id || (ChatFilterTabHidden(session, id) == hidden)) {
		return;
	}
	session->local().writePref<bool>(
		details::ChatFilterTabVisibilityPrefKey(id),
		hidden);
	details::ChatFilterTabVisibilityChanges().fire(std::move(session));
}

[[nodiscard]] inline rpl::producer<not_null<Main::Session*>>
ChatFilterTabVisibilityChanges() {
	return details::ChatFilterTabVisibilityChanges().events();
}

[[nodiscard]] inline std::vector<FilterId> VisibleChatFilterTabIds(
		not_null<Main::Session*> session) {
	const auto &list = session->data().chatsFilters().list();
	auto result = std::vector<FilterId>();
	result.reserve(list.size());
	for (const auto &filter : list) {
		if (!filter.id() || !ChatFilterTabHidden(session, filter.id())) {
			result.push_back(filter.id());
		}
	}
	return result;
}

} // namespace Ui
