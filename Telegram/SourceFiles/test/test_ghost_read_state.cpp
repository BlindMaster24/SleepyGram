// This file is part of Telegram Desktop,
// the official desktop application for the Telegram messaging service.
//
// For license and copyright information please follow this link:
// https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
#include "test/test_ghost_read_state.h"

#include "ayu/data/ghost_read_state.h"

namespace Test {

bool RunGhostReadStateModelTests() {
	auto state = Ayu::GhostReadState();
	state.advance(1, 10, 0, 30);
	state.advance(1, 10, 0, 20);
	if (!state.isHiddenAsRead(1, 10, 0, 30)
		|| state.isHiddenAsRead(1, 10, 0, 31)) {
		return false;
	}
	if (state.isHiddenAsRead(2, 10, 0, 30)
		|| state.isHiddenAsRead(1, 11, 0, 30)
		|| state.isHiddenAsRead(1, 10, 5, 30)) {
		return false;
	}
	state.advance(1, 10, 5, 40);
	if (!state.isHiddenAsRead(1, 10, 5, 40)
		|| state.isHiddenAsRead(1, 10, 0, 40)) {
		return false;
	}
	state.markManuallyUnread(1, 10, 0);
	if (state.isHiddenAsRead(1, 10, 0, 30)
		|| !state.isHiddenAsRead(1, 10, 5, 40)) {
		return false;
	}
	state.advance(1, 10, 0, 35);
	if (!state.isHiddenAsRead(1, 10, 0, 35)) {
		return false;
	}
	state.markManuallyUnread(1, 10, 0);
	state.clear(1, 10, 0);
	if (state.find(1, 10, 0)
		|| !state.isHiddenAsRead(1, 10, 5, 40)) {
		return false;
	}
	state.clearAccount(1);
	return state.all().empty();
}

} // namespace Test
