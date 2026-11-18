// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_coordinator.h"

#include <memory>

namespace Ayu::ProfileSets {
class AccountStoragePlan;
class MigrationController;
struct AccountId;
} // namespace Ayu::ProfileSets

namespace Ayu::EmergencyActions {

struct ScopedSessionBinding;

[[nodiscard]] std::unique_ptr<RemoteSessionEffect> MakeMtprotoSessionEffect(
	const InstallationId &currentInstallation,
	const EmergencyActionJournal &approved,
	const ProfileSets::MigrationController &workspace,
	const ProfileSets::AccountStoragePlan &grants,
	std::span<const ScopedSessionBinding> bindings);

[[nodiscard]] SessionId TelegramRemoteSessionId(uint64_t hash);

namespace details {

enum class SessionRequestKind {
	RevokeSelected,
	RevokeAllOther,
	LogoutCurrent,
};

struct SessionRequest final {
	SessionRequestKind kind = SessionRequestKind::LogoutCurrent;
	uint64_t hash = 0;

	friend bool operator==(const SessionRequest &, const SessionRequest &) = default;
};

class SessionRequestTransport {
public:
	virtual ~SessionRequestTransport() = default;
	[[nodiscard]] virtual EffectResult send(
		const AccountId &accountId,
		std::span<const SessionRequest> requests,
		CoordinatorClock::TimePoint deadline) = 0;

};

[[nodiscard]] std::unique_ptr<RemoteSessionEffect> MakeBoundSessionEffect(
	const InstallationId &currentInstallation,
	const EmergencyActionJournal &approved,
	std::unique_ptr<SessionRequestTransport> transport);

} // namespace details
} // namespace Ayu::EmergencyActions
