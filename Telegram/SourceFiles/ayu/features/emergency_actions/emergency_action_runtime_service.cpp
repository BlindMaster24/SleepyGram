// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_action_runtime_service.h"

#include <algorithm>
#include <ranges>
#include <utility>

namespace Ayu::EmergencyActions {
namespace {

bool MatchesSeedPlan(
		const EmergencyActionJournal &stored,
		const EmergencyActionJournal &seed) {
	if (stored.operationId != seed.operationId
		|| stored.ruleId != seed.ruleId
		|| stored.installationId != seed.installationId
		|| stored.action != seed.action
		|| stored.targetScope != seed.targetScope
		|| stored.safeDestination != seed.safeDestination
		|| stored.safeProfileId != seed.safeProfileId
		|| stored.accounts.size() != seed.accounts.size()) {
		return false;
	}
	for (auto i = size_t(0); i != stored.accounts.size(); ++i) {
		const auto &a = stored.accounts[i];
		const auto &b = seed.accounts[i];
		if (a.accountId != b.accountId
			|| a.remoteSessionTarget != b.remoteSessionTarget
			|| a.sessionIdsForRevoke != b.sessionIdsForRevoke
			|| (b.localDataClear.state != EffectState::NotRequested
				&& a.localDataClear.state == EffectState::NotRequested)) {
			return false;
		}
	}
	return true;
}

} // namespace

EmergencyActionRuntimeService::EmergencyActionRuntimeService(
		const RuleConfiguration &configuration,
		LiveInstallationReader readLiveInstallation,
		JournalStore &store,
		RemoteSessionEffect &remote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock)
: _configuration(configuration)
, _readLiveInstallation(std::move(readLiveInstallation))
, _store(store)
, _remote(remote)
, _local(local)
, _destination(destination)
, _clock(clock) {
}

RuntimeServiceReport EmergencyActionRuntimeService::Submit(
		LockScreenSubmit lockScreen,
		const CredentialVerifier &verifiedCredential) {
	auto result = RuntimeServiceReport{
		.route = DispatchLockScreenPasscode(
			lockScreen,
			_configuration,
			verifiedCredential),
	};
	const auto match = std::get_if<EmergencyActionMatch>(&result.route);
	if (!match) {
		result.status = RuntimeServiceStatus::NoEmergencyMatch;
		return result;
	}
	const auto draft = std::ranges::find(
		_configuration.emergencyRules,
		match->id,
		&EmergencyRuleDraft::id);
	if (draft == _configuration.emergencyRules.end()
		|| !draft->confirmed
		|| draft->confirmed->revision != draft->revision
		|| draft->confirmed->reviewedRule != draft->rule
		|| draft->confirmed->reviewedVerifier != draft->verifier) {
		result.status = RuntimeServiceStatus::Rejected;
		return result;
	}
	if (draft->rule.action != EmergencyAction::ResetAccountData) {
		result.status = RuntimeServiceStatus::UnsupportedAction;
		return result;
	}
	if (!_readLiveInstallation) {
		result.status = RuntimeServiceStatus::Rejected;
		return result;
	}
	const auto live = _readLiveInstallation();
	if (!live || live->id != _configuration.activeInstallationId) {
		result.status = RuntimeServiceStatus::StaleReview;
		return result;
	}
	const auto &reviewed = draft->confirmed->reviewedPlan;
	const auto current = BuildDryRunPlan(
		reviewed.operationId,
		draft->rule,
		*live);
	if (current.status != DryRunStatus::Ready || current != reviewed) {
		result.status = RuntimeServiceStatus::StaleReview;
		return result;
	}
	auto seed = MakeJournal(current);
	if (!seed) {
		result.status = RuntimeServiceStatus::Rejected;
		return result;
	}
	auto journal = EmergencyActionJournal();
	const auto seedBytes = EncodeJournal(*seed);
	if (seedBytes.empty()) {
		result.status = RuntimeServiceStatus::Rejected;
		return result;
	}
	switch (_store.createAtomically(seed->operationId, seedBytes)) {
	case JournalCreateResult::Created:
		journal = std::move(*seed);
		break;
	case JournalCreateResult::Failed:
		result.status = RuntimeServiceStatus::CheckpointFailed;
		return result;
	case JournalCreateResult::AlreadyExists: {
		const auto storedBytes = _store.read(
			seed->operationId,
			kMaxJournalBytes);
		const auto stored = DecodeJournal(storedBytes);
		if (!stored || stored->operationId != seed->operationId
			|| !MatchesSeedPlan(*stored, *seed)) {
			result.status = RuntimeServiceStatus::Rejected;
			return result;
		}
		journal = *stored;
		break;
	}
	}
	result.coordinator = RunResetCoordinator(
		journal,
		_store,
		_remote,
		_local,
		_destination,
		_clock);
	result.status = (result.coordinator->result == CoordinatorResult::CheckpointFailed)
		? RuntimeServiceStatus::CheckpointFailed
		: (result.coordinator->result == CoordinatorResult::UnsupportedAction)
			? RuntimeServiceStatus::UnsupportedAction
			: (result.coordinator->result == CoordinatorResult::Rejected)
				? RuntimeServiceStatus::Rejected
				: RuntimeServiceStatus::Coordinated;
	return result;
}

} // namespace Ayu::EmergencyActions
