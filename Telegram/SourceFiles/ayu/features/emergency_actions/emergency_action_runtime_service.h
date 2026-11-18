// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_coordinator.h"
#include "ayu/features/emergency_actions/emergency_rule_dispatch.h"

#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace Ayu::EmergencyActions {

struct EmergencyRuleAuthority;
class EmergencyRuleTicket;

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
using RemoteSessionProvider = std::function<std::unique_ptr<RemoteSessionEffect>(
	const EmergencyActionJournal&)>;
// Call admission synchronously while the authenticated authority is current.
using WithCurrentEmergencyAuthority = std::function<bool(
	const EmergencyRuleAuthority&,
	const std::function<void()>&)>;

class EmergencyActionRuntimeService final {
public:
	EmergencyActionRuntimeService(
		LiveInstallationReader readLiveInstallation,
		JournalStore &store,
		RemoteSessionProvider provideRemote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock);
	EmergencyActionRuntimeService(
		const RuleConfiguration &configuration,
		LiveInstallationReader readLiveInstallation,
		JournalStore &store,
		RemoteSessionEffect &remote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock);
	EmergencyActionRuntimeService(
		const RuleConfiguration &configuration,
		LiveInstallationReader readLiveInstallation,
		JournalStore &store,
		RemoteSessionProvider provideRemote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock);

	[[nodiscard]] RuntimeServiceReport Submit(
		LockScreenSubmit,
		const CredentialVerifier &verifiedCredential);
	[[nodiscard]] RuntimeServiceReport SubmitVerified(
		LockScreenSubmit,
		const EmergencyRuleTicket &ticket,
		const WithCurrentEmergencyAuthority &withCurrentAuthority);

private:
	[[nodiscard]] RuntimeServiceReport SubmitRule(
		RuntimeServiceReport result,
		const EmergencyRule &rule,
		const OperationId &operationId,
		const std::function<bool(const std::function<void()>&)> &admit);

	const RuleConfiguration *_configuration = nullptr;
	LiveInstallationReader _readLiveInstallation;
	JournalStore &_store;
	RemoteSessionEffect *_remote = nullptr;
	RemoteSessionProvider _provideRemote;
	LocalAccountEffect &_local;
	SafeDestinationEffect &_destination;
	const CoordinatorClock &_clock;

};

} // namespace Ayu::EmergencyActions
