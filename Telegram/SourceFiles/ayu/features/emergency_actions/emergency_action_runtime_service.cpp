// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_action_runtime_service.h"

#include "ayu/features/emergency_actions/emergency_rule_vault.h"

#include <algorithm>
#include <ranges>
#include <utility>

namespace Ayu::EmergencyActions {
namespace {

bool AccountMatchesRule(const JournalAccount &account, const EmergencyRule &rule) {
	if (account.localDataClear.state == EffectState::NotRequested
		|| (rule.targetScope == TargetScope::SelectedAccounts
			&& std::ranges::find(rule.selectedAccountIds, account.accountId)
				== rule.selectedAccountIds.end())) {
		return false;
	}
	const auto policy = std::ranges::find(
		rule.remoteSessionPolicies,
		account.accountId,
		&RemoteSessionPolicy::accountId);
	return (policy == rule.remoteSessionPolicies.end())
		? account.remoteSessionTarget == RemoteSessionTargetKind::None
		: account.remoteSessionTarget == policy->kind
			&& std::ranges::all_of(account.sessionIdsForRevoke, [&](const auto &id) {
				return std::ranges::find(policy->selectedSessionIds, id)
					!= policy->selectedSessionIds.end();
			});
}

bool MatchesConfirmedRule(
		const EmergencyActionJournal &journal,
		const EmergencyRule &rule) {
	return journal.ruleId == rule.id
		&& journal.installationId == rule.installationId
		&& journal.action == rule.action
		&& journal.targetScope == rule.targetScope
		&& (journal.safeDestination == SafeDestinationKind::AddAccount
			|| (journal.safeDestination == SafeDestinationKind::Profile
				&& journal.safeProfileId == rule.safeProfileId))
		&& std::ranges::all_of(journal.accounts, [&](const auto &account) {
			return AccountMatchesRule(account, rule);
		});
}

RuntimeServiceStatus RuntimeStatus(CoordinatorResult result) {
	switch (result) {
	case CoordinatorResult::Complete:
	case CoordinatorResult::Partial: return RuntimeServiceStatus::Coordinated;
	case CoordinatorResult::Rejected: return RuntimeServiceStatus::Rejected;
	case CoordinatorResult::UnsupportedAction: return RuntimeServiceStatus::UnsupportedAction;
	case CoordinatorResult::CheckpointFailed: return RuntimeServiceStatus::CheckpointFailed;
	}
	return RuntimeServiceStatus::Rejected;
}

} // namespace

ResetRecoveryReport ResumePendingResetOperations(
		JournalStore &store,
		const InstallationId &installationId,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination) {
	auto result = ResetRecoveryReport();
	const auto lease = store.tryAcquireExecution();
	if (!lease || !installationId.valid()) {
		return result;
	}
	const auto ids = store.operationIds();
	if (!ids) {
		return result;
	}
	auto journals = std::vector<EmergencyActionJournal>();
	for (const auto &id : *ids) {
		auto journal = LoadJournal(store, id);
		if (!journal || journal->installationId != installationId
			|| journal->action != EmergencyAction::ResetAccountData) {
			return result;
		}
		journals.push_back(std::move(*journal));
	}
	result.canStartAccounts = true;
	for (auto &journal : journals) {
		const auto report = ResumeResetCoordinator(journal, *lease, local, destination);
		result.operations.push_back(report);
		if (!report.safeDestinationReady
			|| (report.result != CoordinatorResult::Complete
				&& report.result != CoordinatorResult::Partial)) {
			result.canStartAccounts = false;
			break;
		}
	}
	return result;
}

EmergencyActionRuntimeService::EmergencyActionRuntimeService(
		const RuleConfiguration &configuration,
		LiveInstallationReader readLiveInstallation,
		JournalStore &store,
		RemoteSessionEffect &remote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock)
: EmergencyActionRuntimeService(
	configuration,
	std::move(readLiveInstallation),
	store,
	RemoteSessionProvider(),
	local,
	destination,
	clock) {
	_remote = &remote;
}

EmergencyActionRuntimeService::EmergencyActionRuntimeService(
		const RuleConfiguration &configuration,
		LiveInstallationReader readLiveInstallation,
		JournalStore &store,
		RemoteSessionProvider provideRemote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock)
: EmergencyActionRuntimeService(
	std::move(readLiveInstallation),
	store,
	std::move(provideRemote),
	local,
	destination,
	clock) {
	_configuration = &configuration;
}

EmergencyActionRuntimeService::EmergencyActionRuntimeService(
		LiveInstallationReader readLiveInstallation,
		JournalStore &store,
		RemoteSessionProvider provideRemote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock)
: _readLiveInstallation(std::move(readLiveInstallation))
, _store(store)
, _provideRemote(std::move(provideRemote))
, _local(local)
, _destination(destination)
, _clock(clock) {
}

RuntimeServiceReport EmergencyActionRuntimeService::Submit(
		LockScreenSubmit lockScreen,
		const CredentialVerifier &verifiedCredential) {
	if (!_configuration) {
		return {};
	}
	auto result = RuntimeServiceReport{
		.route = DispatchLockScreenPasscode(
			lockScreen,
			*_configuration,
			verifiedCredential),
	};
	const auto match = std::get_if<EmergencyActionMatch>(&result.route);
	if (!match) {
		result.status = RuntimeServiceStatus::NoEmergencyMatch;
		return result;
	}
	const auto draft = std::ranges::find(
		_configuration->emergencyRules,
		match->id,
		&EmergencyRuleDraft::id);
	if (draft == _configuration->emergencyRules.end()
		|| !draft->confirmed
		|| draft->confirmed->revision != draft->revision
		|| draft->confirmed->reviewedRule != draft->rule
		|| draft->confirmed->reviewedVerifier != draft->verifier) {
		result.status = RuntimeServiceStatus::Rejected;
		return result;
	}
	return SubmitRule(
		std::move(result),
		draft->rule,
		draft->confirmed->reviewedPlan.operationId,
		[](const std::function<void()> &admit) {
			admit();
			return true;
		});
}

RuntimeServiceReport EmergencyActionRuntimeService::SubmitVerified(
		LockScreenSubmit,
		const EmergencyRuleTicket &ticket,
		const WithCurrentEmergencyAuthority &withCurrentAuthority) {
	if (!withCurrentAuthority) {
		return {};
	}
	const auto &details = ticket.details();
	return SubmitRule(
		{ .route = EmergencyActionMatch{ details.actionId } },
		details.rule,
		details.operationId,
		[&](const std::function<void()> &admit) {
			return withCurrentAuthority(ticket.authority(), admit);
		});
}

RuntimeServiceReport EmergencyActionRuntimeService::SubmitRule(
		RuntimeServiceReport result,
		const EmergencyRule &rule,
		const OperationId &operationId,
		const std::function<bool(const std::function<void()>&)> &admit) {
	if (rule.action != EmergencyAction::ResetAccountData) {
		result.status = RuntimeServiceStatus::UnsupportedAction;
		return result;
	}
	const auto lease = _store.tryAcquireExecution();
	if (!lease) {
		result.status = RuntimeServiceStatus::CheckpointFailed;
		return result;
	}
	auto journal = std::optional<EmergencyActionJournal>();
	auto prepared = false;
	auto resumed = false;
	auto entered = false;
	const auto authorized = admit([&] {
		if (entered) {
			return;
		}
		entered = true;
		journal = LoadJournal(_store, operationId);
		if (journal) {
			resumed = true;
			prepared = MatchesConfirmedRule(*journal, rule);
			return;
		}
		const auto live = _readLiveInstallation ? _readLiveInstallation() : std::nullopt;
		if (!live || live->id != rule.installationId) {
			result.status = RuntimeServiceStatus::StaleReview;
			return;
		}
		const auto current = BuildDryRunPlan(operationId, rule, *live);
		if (current.status != DryRunStatus::Ready) {
			result.status = RuntimeServiceStatus::StaleReview;
			return;
		}
		journal = MakeJournal(current);
		if (!journal) {
			return;
		}
		const auto seedBytes = EncodeJournal(*journal);
		if (seedBytes.empty()) {
			return;
		}
		prepared = _store.createAtomically(operationId, seedBytes)
			== JournalCreateResult::Created;
		if (!prepared) {
			result.status = RuntimeServiceStatus::CheckpointFailed;
		}
	});
	if (!authorized || !entered) {
		result.status = RuntimeServiceStatus::StaleReview;
		return result;
	}
	if (!prepared) {
		return result;
	}
	if (resumed) {
		result.coordinator = ResumeResetCoordinator(*journal, *lease, _local, _destination);
		result.status = RuntimeStatus(result.coordinator->result);
		return result;
	}
	auto provided = std::unique_ptr<RemoteSessionEffect>();
	if (_provideRemote) {
		try {
			provided = _provideRemote(*journal);
		} catch (...) {
		}
	}
	const auto remote = provided ? provided.get() : _remote;
	result.coordinator = remote
		? RunResetCoordinator(*journal, *lease, *remote, _local, _destination, _clock)
		: ResumeResetCoordinator(*journal, *lease, _local, _destination);
	result.status = RuntimeStatus(result.coordinator->result);
	return result;
}

} // namespace Ayu::EmergencyActions
