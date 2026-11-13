// This file is part of Telegram Desktop,
// the official desktop application for the Telegram messaging service.
//
// For license and copyright information please follow this link:
// https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
#pragma once

#include <algorithm>
#include <compare>
#include <cstdint>
#include <map>
#include <utility>

namespace Ayu {

struct GhostReadScope {
	std::uint64_t accountId = 0;
	std::uint64_t peerId = 0;
	std::uint64_t topicRootId = 0;

	friend auto operator<=>(
		const GhostReadScope &,
		const GhostReadScope &) = default;
};

struct GhostReadWatermark {
	std::int64_t readTill = 0;
	bool manuallyUnread = false;
};

class GhostReadState final {
public:
	void advance(
			std::uint64_t accountId,
			std::uint64_t peerId,
			std::uint64_t topicRootId,
			std::int64_t readTill) {
		if (!accountId || !peerId || (readTill <= 0)) {
			return;
		}
		auto &state = _watermarks[{ accountId, peerId, topicRootId }];
		state.readTill = std::max(state.readTill, readTill);
		state.manuallyUnread = false;
	}

	void markManuallyUnread(
			std::uint64_t accountId,
			std::uint64_t peerId,
			std::uint64_t topicRootId) {
		if (!accountId || !peerId) {
			return;
		}
		_watermarks[{ accountId, peerId, topicRootId }].manuallyUnread = true;
	}

	void clear(
			std::uint64_t accountId,
			std::uint64_t peerId,
			std::uint64_t topicRootId) {
		_watermarks.erase({ accountId, peerId, topicRootId });
	}

	void clearAccount(std::uint64_t accountId) {
		for (auto i = _watermarks.begin(); i != _watermarks.end();) {
			if (i->first.accountId == accountId) {
				i = _watermarks.erase(i);
			} else {
				++i;
			}
		}
	}

	[[nodiscard]] const GhostReadWatermark *find(
			std::uint64_t accountId,
			std::uint64_t peerId,
			std::uint64_t topicRootId) const {
		const auto i = _watermarks.find({ accountId, peerId, topicRootId });
		return (i == _watermarks.end()) ? nullptr : &i->second;
	}

	[[nodiscard]] bool isHiddenAsRead(
			std::uint64_t accountId,
			std::uint64_t peerId,
			std::uint64_t topicRootId,
			std::int64_t messageId) const {
		const auto state = find(accountId, peerId, topicRootId);
		if (state && state->manuallyUnread) {
			return false;
		}
		if (topicRootId) {
			const auto peerState = find(accountId, peerId, 0);
			if (peerState && peerState->manuallyUnread) {
				return false;
			}
		}
		return state
			&& !state->manuallyUnread
			&& (messageId > 0)
			&& (messageId <= state->readTill);
	}

	[[nodiscard]] const std::map<GhostReadScope, GhostReadWatermark> &all() const {
		return _watermarks;
	}

	void replace(std::map<GhostReadScope, GhostReadWatermark> watermarks) {
		_watermarks = std::move(watermarks);
	}

private:
	std::map<GhostReadScope, GhostReadWatermark> _watermarks;
};

} // namespace Ayu
