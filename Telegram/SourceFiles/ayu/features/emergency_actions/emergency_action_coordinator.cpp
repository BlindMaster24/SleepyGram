// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_action_coordinator.h"

#include <algorithm>
#include <chrono>
#include <ranges>
#include <utility>

namespace Ayu::EmergencyActions {
namespace {

constexpr auto kRemotePhaseBudget = std::chrono::seconds(5);

bool CanBeginLocal(const JournalEffectState &state) {
	return state.state == EffectState::Pending
		|| state.state == EffectState::FailedRetryable
		|| state.state == EffectState::Unconfirmed;
}

bool IsSeedJournal(const EmergencyActionJournal &journal) {
	const auto unstarted = [](const JournalEffectState &effect) {
		return effect.state == EffectState::NotRequested
			|| effect.state == EffectState::Pending;
	};
	return unstarted(journal.safeDestinationActivation)
		&& std::ranges::all_of(journal.accounts, [&](const JournalAccount &account) {
			return unstarted(account.localDataClear)
				&& unstarted(account.remoteSessionRevoke)
				&& unstarted(account.currentSessionLogout);
		});
}

bool Claim(
		EmergencyActionJournal &journal,
		JournalStore &store,
		JournalEffect effect,
		std::optional<AccountId> accountId) {
	auto candidate = journal;
	if (BeginEffect(candidate, effect, std::move(accountId))
		!= TransitionResult::Applied
		|| !SaveJournal(store, candidate)) {
		return false;
	}
	journal = std::move(candidate);
	return true;
}

bool SaveOutcome(
		EmergencyActionJournal &journal,
		JournalStore &store,
		JournalEffect effect,
		EffectResult outcome,
		std::optional<AccountId> accountId) {
	auto candidate = journal;
	if (ResolveEffect(candidate, effect, outcome, std::move(accountId))
		!= TransitionResult::Applied
		|| !SaveJournal(store, candidate)) {
		return false;
	}
	journal = std::move(candidate);
	return true;
}

CoordinatorReport Report(
		const EmergencyActionJournal &journal,
		CoordinatorReport result) {
	result.journalStatus = Status(journal);
	result.localCleanupComplete = LocalCleanupComplete(journal);
	const auto activation = journal.safeDestinationActivation.state;
	result.safeDestinationReady = result.localCleanupComplete
		&& (activation == EffectState::NotRequested
			|| activation == EffectState::Succeeded);
	if (result.result == CoordinatorResult::Partial) {
		result.result = (result.journalStatus == JournalStatus::Complete)
			? CoordinatorResult::Complete
			: CoordinatorResult::Partial;
	}
	return result;
}

bool RunRemotePhase(
		EmergencyActionJournal &journal,
		JournalStore &store,
		RemoteSessionEffect &remote,
		const CoordinatorClock &clock,
		CoordinatorReport &report) {
	const auto deadline = clock.now() + kRemotePhaseBudget;
	const auto execute = [&](JournalEffect effect, const AccountId &accountId,
			JournalEffectState state, auto &&apply) {
		if (state.state != EffectState::Pending) {
			return true;
		}
		if (clock.now() >= deadline) {
			report.remoteDeadlineReached = true;
			return true;
		}
		if (!Claim(journal, store, effect, accountId)) {
			return false;
		}
		++report.remoteAttempts;
		auto outcome = EffectResult::Unconfirmed;
		try {
			outcome = apply();
		} catch (...) {
			outcome = EffectResult::Unconfirmed;
		}
		report.remoteDeadlineReached = clock.now() >= deadline;
		return SaveOutcome(journal, store, effect, outcome, accountId);
	};
	for (auto i = size_t(0); i != journal.accounts.size(); ++i) {
		const auto accountId = journal.accounts[i].accountId;
		const auto target = journal.accounts[i].remoteSessionTarget;
		const auto sessionIds = journal.accounts[i].sessionIdsForRevoke;
		if (!execute(
				JournalEffect::RemoteSessionRevoke,
				accountId,
				journal.accounts[i].remoteSessionRevoke,
				[&] { return remote.revoke(accountId, target, sessionIds, deadline); })
			|| !execute(
				JournalEffect::CurrentSessionLogout,
				accountId,
				journal.accounts[i].currentSessionLogout,
				[&] { return remote.logoutCurrent(accountId, deadline); })) {
			return false;
		}
		if (report.remoteDeadlineReached) {
			break;
		}
	}
	return true;
}

CoordinatorReport Run(
		EmergencyActionJournal &journal,
		JournalStore &store,
		LocalAccountEffect &local,
		SafeDestinationEffect *destination,
		RemoteSessionEffect *remote = nullptr,
		const CoordinatorClock *clock = nullptr) {
	auto report = CoordinatorReport();
	const auto saved = LoadJournal(store, journal.operationId);
	if (!saved || EncodeJournal(*saved) != EncodeJournal(journal)) {
		return report;
	}
	const auto expected = destination ? EmergencyAction::ResetAccountData : EmergencyAction::RemoveInstallation;
	if (journal.action != expected) {
		report.result = CoordinatorResult::UnsupportedAction;
		return report;
	}
	if (remote && !IsSeedJournal(journal)) {
		return report;
	}
	report.result = CoordinatorResult::Partial;
	const auto failed = [&] {
		report.result = CoordinatorResult::CheckpointFailed;
		return Report(journal, report);
	};
	auto candidate = journal;
	if (RecoverInterruptedEffects(candidate)) {
		if (!SaveJournal(store, candidate)) {
			return failed();
		}
		journal = std::move(candidate);
	}
	if (remote && !RunRemotePhase(journal, store, *remote, *clock, report)) {
		return failed();
	}
	candidate = journal;
	if (FinishRemotePhase(candidate)) {
		if (!SaveJournal(store, candidate)) {
			return failed();
		}
		journal = std::move(candidate);
	}
	for (auto i = size_t(0); i != journal.accounts.size(); ++i) {
		const auto accountId = journal.accounts[i].accountId;
		const auto state = journal.accounts[i].localDataClear;
		if (!CanBeginLocal(state)) {
			continue;
		}
		if (!Claim(
				journal,
				store,
				JournalEffect::LocalDataClear,
				accountId)) {
			return failed();
		}
		++report.localAttempts;
		auto outcome = EffectResult::Unconfirmed;
		try {
			outcome = local.clear(accountId);
		} catch (...) {
			outcome = EffectResult::Unconfirmed;
		}
		if (!SaveOutcome(
				journal,
				store,
				JournalEffect::LocalDataClear,
				outcome,
				accountId)) {
			return failed();
		}
	}
	if (destination && LocalCleanupComplete(journal)
		&& CanBeginLocal(journal.safeDestinationActivation)) {
		if (!Claim(
				journal,
				store,
				JournalEffect::SafeDestinationActivation,
				std::nullopt)) {
			return failed();
		}
		report.safeDestinationAttempted = true;
		auto outcome = EffectResult::Unconfirmed;
		try {
			outcome = destination->activate(
				journal.safeDestination,
				journal.safeProfileId);
		} catch (...) {
			outcome = EffectResult::Unconfirmed;
		}
		if (!SaveOutcome(
				journal,
				store,
				JournalEffect::SafeDestinationActivation,
				outcome,
				std::nullopt)) {
			return failed();
		}
	}
	return Report(journal, report);
}

} // namespace

CoordinatorReport RunResetCoordinator(
		EmergencyActionJournal &journal,
		const JournalStore::ExecutionLease &lease,
		RemoteSessionEffect &remote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock) {
	return Run(journal, lease.store(), local, &destination, &remote, &clock);
}

CoordinatorReport ResumeResetCoordinator(
		EmergencyActionJournal &journal,
		const JournalStore::ExecutionLease &lease,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination) {
	return Run(journal, lease.store(), local, &destination);
}

CoordinatorReport RunInstallationCleanupCoordinator(
		EmergencyActionJournal &journal,
		const JournalStore::ExecutionLease &lease,
		RemoteSessionEffect *remote,
		LocalAccountEffect &local,
		const CoordinatorClock &clock) {
	return Run(journal, lease.store(), local, nullptr, remote, &clock);
}

} // namespace Ayu::EmergencyActions
