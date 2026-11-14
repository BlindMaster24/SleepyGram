// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_action_coordinator.h"

#include <algorithm>
#include <chrono>
#include <ranges>
#include <utility>

namespace Ayu::EmergencyActions {
namespace {

constexpr auto kRemotePhaseBudget = std::chrono::seconds(5);

bool CanBegin(const JournalEffectState &state, RetryMode mode) {
	return state.state == EffectState::Pending
		|| state.state == EffectState::FailedRetryable
		|| (state.state == EffectState::Unconfirmed
			&& mode == RetryMode::ExplicitlyRetryUnconfirmed);
}

bool Claim(
		EmergencyActionJournal &journal,
		JournalStore &store,
		JournalEffect effect,
		std::optional<AccountId> accountId,
		RetryMode retryMode) {
	auto candidate = journal;
	if (BeginEffect(candidate, effect, std::move(accountId), retryMode)
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
	return ResolveEffect(journal, effect, outcome, std::move(accountId))
		== TransitionResult::Applied
		&& SaveJournal(store, journal);
}

CoordinatorReport Report(
		EmergencyActionJournal &journal,
		CoordinatorReport result) {
	result.journalStatus = Status(journal);
	if (result.result != CoordinatorResult::CheckpointFailed
		&& result.result != CoordinatorResult::Rejected
		&& result.result != CoordinatorResult::UnsupportedAction) {
		result.result = (result.journalStatus == JournalStatus::Complete)
			? CoordinatorResult::Complete
			: CoordinatorResult::Partial;
	}
	return result;
}

} // namespace

CoordinatorReport RunResetCoordinator(
		EmergencyActionJournal &journal,
		JournalStore &store,
		RemoteSessionEffect &remote,
		LocalAccountEffect &local,
		SafeDestinationEffect &destination,
		const CoordinatorClock &clock,
		RetryMode retryMode) {
	auto report = CoordinatorReport();
	if (EncodeJournal(journal).empty()) {
		return Report(journal, report);
	}
	if (journal.action != EmergencyAction::ResetAccountData) {
		report.result = CoordinatorResult::UnsupportedAction;
		return Report(journal, report);
	}
	report.result = CoordinatorResult::Partial;
	const auto recovered = RecoverInterruptedEffects(journal);
	if (recovered && !SaveJournal(store, journal)) {
		report.result = CoordinatorResult::CheckpointFailed;
		return Report(journal, report);
	}
	const auto deadline = clock.now() + kRemotePhaseBudget;
	for (auto i = size_t(0); i != journal.accounts.size(); ++i) {
		const auto accountId = journal.accounts[i].accountId;
		const auto sessionIds = journal.accounts[i].sessionIdsForRevoke;
		const auto state = journal.accounts[i].remoteSessionRevoke;
		const auto localState = journal.accounts[i].localDataClear;
		if (!CanBegin(state, retryMode)
			|| localState.state == EffectState::Succeeded) {
			continue;
		}
		if (clock.now() >= deadline) {
			report.remoteDeadlineReached = true;
			break;
		}
		if (!Claim(
				journal,
				store,
				JournalEffect::RemoteSessionRevoke,
				accountId,
				retryMode)) {
			report.result = CoordinatorResult::CheckpointFailed;
			return Report(journal, report);
		}
		++report.remoteAttempts;
		auto outcome = EffectResult::Unconfirmed;
		try {
			outcome = remote.revoke(
				accountId,
				sessionIds,
				deadline);
		} catch (...) {
			outcome = EffectResult::Unconfirmed;
		}
		if (!SaveOutcome(
				journal,
				store,
				JournalEffect::RemoteSessionRevoke,
				outcome,
				accountId)) {
			report.result = CoordinatorResult::CheckpointFailed;
			return Report(journal, report);
		}
		if (clock.now() >= deadline) {
			report.remoteDeadlineReached = true;
		}
	}
	for (auto i = size_t(0); i != journal.accounts.size(); ++i) {
		const auto accountId = journal.accounts[i].accountId;
		const auto state = journal.accounts[i].localDataClear;
		if (!CanBegin(state, retryMode)) {
			continue;
		}
		if (!Claim(
				journal,
				store,
				JournalEffect::LocalDataClear,
				accountId,
				retryMode)) {
			report.result = CoordinatorResult::CheckpointFailed;
			return Report(journal, report);
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
			report.result = CoordinatorResult::CheckpointFailed;
			return Report(journal, report);
		}
	}
	const auto localComplete = std::ranges::all_of(
		journal.accounts,
		[](const JournalAccount &account) {
			return account.localDataClear.state == EffectState::Succeeded
				|| account.localDataClear.state == EffectState::NotRequested;
		});
	if (localComplete
		&& CanBegin(journal.safeDestinationActivation, retryMode)) {
		if (!Claim(
				journal,
				store,
				JournalEffect::SafeDestinationActivation,
				std::nullopt,
				retryMode)) {
			report.result = CoordinatorResult::CheckpointFailed;
			return Report(journal, report);
		}
		report.safeDestinationAttempted = true;
		auto outcome = EffectResult::Unconfirmed;
		try {
			outcome = destination.activate(
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
			report.result = CoordinatorResult::CheckpointFailed;
			return Report(journal, report);
		}
	}
	return Report(journal, report);
}

} // namespace Ayu::EmergencyActions
