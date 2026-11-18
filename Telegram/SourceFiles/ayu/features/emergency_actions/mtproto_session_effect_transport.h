// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/mtproto_session_effect.h"
#include "ayu/features/profile_sets/profile_sets.h"

namespace Ayu::EmergencyActions {

struct ScopedSessionBinding final {
	AccountId accountId;
	ProfileSets::AccountId scopedAccountId;
	uint64_t expectedUserId = 0;
	bool testEnvironment = false;
};

} // namespace Ayu::EmergencyActions
