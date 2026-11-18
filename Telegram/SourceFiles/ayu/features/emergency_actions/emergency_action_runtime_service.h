// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_coordinator.h"
#include "ayu/features/emergency_actions/emergency_rule_dispatch.h"

#include <functional>
#include <optional>
#include <vector>

namespace Ayu::EmergencyActions {

enum class RuntimeServiceStatus : uint8_t {
	NoEmergencyMatch,
	Rejected,
	StaleReview,
	UnsupportedAction,
	CheckpointFailed,
	Coordinated,
};

struct RuntimeServiceReport final {
	LockScreenRoute route = WrongPasscode();
	RuntimeServiceStatus status = RuntimeServiceStatus::Rejected;
	std::optional<CoordinatorReport> coordinator;
};

struct ResetRecoveryReport final {
	bool canStartAccounts = false;
	std::vector<CoordinatorReport> operations;
};

[[nodiscard]] ResetRecoveryReport ResumePendingResetOperations(
	JournalStore &store,
	const InstallationId &installationId,
	LocalAccountEffect &local,
	SafeDestinationEffect &destination);

using LiveInstallationReader = std::function<
	std::optional<LiveInstallation>()>;

// It accepts only verified fixed-size credentials and the lock-screen token.
class EmergencyActionRuntimeService final {
public:
	EmergencyActionRuntimeService(
		const RuleConfiguration &configuration,
		LiveInstallationReader readLiveInstallation,
		JournalStore &store,
		RemoteSessionEffect &remote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock);

	[[nodiscard]] RuntimeServiceReport Submit(
		LockScreenSubmit,
		const CredentialVerifier &verifiedCredential);

private:
	const RuleConfiguration &_configuration;
	LiveInstallationReader _readLiveInstallation;
	JournalStore &_store;
	RemoteSessionEffect &_remote;
	LocalAccountEffect &_local;
	SafeDestinationEffect &_destination;
	const CoordinatorClock &_clock;
};

} // namespace Ayu::EmergencyActions
