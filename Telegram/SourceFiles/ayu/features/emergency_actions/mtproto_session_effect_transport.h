// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/mtproto_session_effect.h"
#include "ayu/features/profile_sets/profile_sets.h"

namespace Ayu::ProfileSets {
struct AdminVaultAccess;
} // namespace Ayu::ProfileSets

namespace Ayu::EmergencyActions {

struct ScopedSessionBinding final {
	AccountId accountId;
	ProfileSets::AccountId scopedAccountId;
	uint64_t expectedUserId = 0;
	bool testEnvironment = false;
};

struct MtprotoDeviceInventoryEntry final {
	SessionId id;
	bool current = false;
	QString label;
};

[[nodiscard]] std::optional<std::vector<MtprotoDeviceInventoryEntry>>
ReadMtprotoDeviceInventory(
	const ProfileSets::MigrationController &workspace,
	const ProfileSets::AdminVaultAccess &authenticatedMaster,
	ProfileSets::AccountId accountId,
	uint64_t expectedUserId,
	bool testEnvironment,
	CoordinatorClock::TimePoint deadline);

} // namespace Ayu::EmergencyActions
