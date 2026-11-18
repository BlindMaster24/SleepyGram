#include "ayu/features/emergency_actions/emergency_action_coordinator.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace {

using namespace Ayu::EmergencyActions;

int failures = 0;

void Check(const char *name, bool condition) {
	std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
	failures += !condition;
}

DryRunPlan Plan(size_t count = 2) {
	auto result = DryRunPlan{
		.operationId = OperationId("op-coordinator"),
		.ruleId = RuleId("rule-coordinator"),
		.installationId = InstallationId("install-coordinator"),
		.action = EmergencyAction::ResetAccountData,
		.targetScope = TargetScope::SelectedAccounts,
		.safeDestination = SafeDestinationKind::AddAccount,
	};
	for (auto i = size_t(0); i != count; ++i) {
		const auto letter = char('a' + i);
		const auto account = std::string("account-") + letter;
		const auto session = std::string("session-") + letter;
		result.accounts.push_back({
			.accountId = AccountId(account),
			.wouldClearLocalData = true,
			.remoteTarget = RemoteSessionTargetKind::SelectedSessions,
			.remoteTargetWasConfigured = true,
			.sessionIdsForRevokeRequest = { SessionId(session) },
		});
	}
	return result;
}

struct FixtureStore final : JournalStore {
	struct Lease final : ExecutionLease {
		explicit Lease(JournalStore &store) : ExecutionLease(store) {
		}
	};

	std::map<std::string, std::vector<std::byte>> values;
	int writes = 0;
	int failWrite = 0;

	std::unique_ptr<ExecutionLease> tryAcquireExecution() override {
		return std::make_unique<Lease>(*this);
	}

	std::optional<std::vector<OperationId>> operationIds() override {
		auto ids = std::vector<OperationId>();
		for (const auto &[id, bytes] : values) {
			ids.emplace_back(id);
		}
		return ids;
	}

	JournalCreateResult createAtomically(
			const OperationId &id,
			std::span<const std::byte> bytes) override {
		if (values.contains(id.value)) {
			return JournalCreateResult::AlreadyExists;
		}
		++writes;
		if (writes == failWrite) {
			return JournalCreateResult::Failed;
		}
		values.emplace(id.value, std::vector<std::byte>(bytes.begin(), bytes.end()));
		return JournalCreateResult::Created;
	}

	std::vector<std::byte> read(
			const OperationId &id,
			size_t maximumBytes) override {
		const auto i = values.find(id.value);
		return (i == values.end() || i->second.size() > maximumBytes)
			? std::vector<std::byte>()
			: i->second;
	}

	bool writeAtomically(
			const OperationId &id,
			std::span<const std::byte> bytes) override {
		++writes;
		if (writes == failWrite) {
			return false;
		}
		auto temporary = std::vector<std::byte>(bytes.begin(), bytes.end());
		values[id.value].swap(temporary);
		return true;
	}
};

struct FakeClock final : CoordinatorClock {
	TimePoint value;

	TimePoint now() const override {
		return value;
	}

	void advance(std::chrono::seconds duration) {
		value += duration;
	}
};

struct FakeRemote final : RemoteSessionEffect {
	FakeRemote(
			FixtureStore *store,
			FakeClock *clock,
			std::vector<std::string> *events)
	: store(store), clock(clock), events(events) {
	}

	FixtureStore *store = nullptr;
	FakeClock *clock = nullptr;
	std::vector<std::string> *events = nullptr;
	std::map<std::string, EffectResult> results;
	std::vector<std::string> calledAccountIds;
	std::vector<CoordinatorClock::TimePoint> deadlines;
	std::vector<RemoteSessionTargetKind> remoteTargets;
	std::vector<std::vector<SessionId>> targets;
	std::chrono::seconds advanceAfterFirstCall = std::chrono::seconds(0);
	int calls = 0;
	bool claimsObserved = true;

	EffectResult revoke(
			const AccountId &accountId,
			RemoteSessionTargetKind target,
			std::span<const SessionId> sessionIds,
			CoordinatorClock::TimePoint deadline) override {
		++calls;
		calledAccountIds.push_back(accountId.value);
		deadlines.push_back(deadline);
		remoteTargets.push_back(target);
		targets.emplace_back(sessionIds.begin(), sessionIds.end());
		const auto persisted = LoadJournal(*store, OperationId("op-coordinator"));
		const auto claimSaved = persisted && [&] {
			const auto account = std::ranges::find(
				persisted->accounts,
				accountId,
				&JournalAccount::accountId);
			return account != persisted->accounts.end()
				&& account->remoteSessionRevoke.state == EffectState::InProgress;
		}();
		claimsObserved = claimsObserved
			&& claimSaved;
		events->push_back("remote:" + accountId.value);
		if (calls == 1 && advanceAfterFirstCall.count()) {
			clock->advance(advanceAfterFirstCall);
		}
		const auto i = results.find(accountId.value);
		return (i == results.end())
			? EffectResult::ConfirmedSuccess
			: i->second;
	}
};

struct FakeLocal final : LocalAccountEffect {
	FakeLocal(FixtureStore *store, std::vector<std::string> *events)
	: store(store), events(events) {
	}

	FixtureStore *store = nullptr;
	std::vector<std::string> *events = nullptr;
	std::vector<std::string> calls;
	bool claimsObserved = true;

	EffectResult clear(const AccountId &accountId) override {
		calls.push_back(accountId.value);
		const auto persisted = LoadJournal(*store, OperationId("op-coordinator"));
		const auto claimSaved = persisted && [&] {
			const auto account = std::ranges::find(
				persisted->accounts,
				accountId,
				&JournalAccount::accountId);
			return account != persisted->accounts.end()
				&& account->localDataClear.state == EffectState::InProgress;
		}();
		claimsObserved = claimsObserved
			&& claimSaved;
		events->push_back("local:" + accountId.value);
		return EffectResult::ConfirmedSuccess;
	}
};

struct FakeDestination final : SafeDestinationEffect {
	FakeDestination(FixtureStore *store, std::vector<std::string> *events)
	: store(store), events(events) {
	}

	FixtureStore *store = nullptr;
	std::vector<std::string> *events = nullptr;
	bool claimsObserved = true;
	int calls = 0;

	EffectResult activate(
			SafeDestinationKind kind,
			const ProfileId &) override {
		++calls;
		const auto persisted = LoadJournal(*store, OperationId("op-coordinator"));
		claimsObserved = claimsObserved
			&& persisted
			&& persisted->safeDestinationActivation.state == EffectState::InProgress;
		claimsObserved = claimsObserved
			&& kind == SafeDestinationKind::AddAccount;
		events->push_back("destination");
		return EffectResult::ConfirmedSuccess;
	}
};

struct Fixtures final {
	Fixtures()
	: remote(&store, &clock, &events)
	, local(&store, &events)
	, destination(&store, &events)
	, journal(MakeJournal(Plan()).value()) {
	}

	CoordinatorReport start() {
		store.values.emplace(journal.operationId.value, EncodeJournal(journal));
		const auto lease = store.tryAcquireExecution();
		return RunResetCoordinator(journal, *lease, remote, local, destination, clock);
	}

	FixtureStore store;
	FakeClock clock;
	std::vector<std::string> events;
	FakeRemote remote;
	FakeLocal local;
	FakeDestination destination;
	EmergencyActionJournal journal;
};

void RemoteClaimsAndSharedDeadlinePrecedeLocalEffects() {
	auto f = Fixtures();
	const auto report = f.start();
	const auto deadline = CoordinatorClock::TimePoint{} + std::chrono::seconds(5);
	Check("remote-claims-are-saved-before-injected-effects",
		f.remote.claimsObserved && f.local.claimsObserved
		&& f.destination.claimsObserved);
	Check("remote-phase-uses-exact-stable-targets-and-one-deadline",
		f.remote.calls == 2
		&& f.remote.targets == std::vector<std::vector<SessionId>>{
			{ SessionId("session-a") }, { SessionId("session-b") } }
		&& f.remote.remoteTargets == std::vector<RemoteSessionTargetKind>{
			RemoteSessionTargetKind::SelectedSessions,
			RemoteSessionTargetKind::SelectedSessions }
		&& f.remote.deadlines == std::vector<CoordinatorClock::TimePoint>{
			deadline, deadline });
	Check("order-is-remote-then-local-then-safe-destination",
		f.events == std::vector<std::string>{
			"remote:account-a",
			"remote:account-b",
			"local:account-a",
			"local:account-b",
			"destination" });
	Check("full-success-is-recorded-as-complete",
		report.result == CoordinatorResult::Complete
		&& report.journalStatus == JournalStatus::Complete
		&& report.remoteAttempts == 2
		&& report.localAttempts == 2);
}

void AllOtherSessionsRemainsAServerScope() {
	auto plan = Plan(1);
	plan.accounts.front().remoteTarget = RemoteSessionTargetKind::AllOtherSessions;
	auto journalValue = MakeJournal(plan);
	Check("all-other-target-survives-journal-codec",
		journalValue
		&& journalValue->accounts.front().remoteSessionTarget
			== RemoteSessionTargetKind::AllOtherSessions
		&& journalValue->accounts.front().remoteSessionRevoke.state
			== EffectState::Pending
		&& journalValue->accounts.front().sessionIdsForRevoke.empty());
	if (!journalValue) return;
	const auto decoded = DecodeJournal(EncodeJournal(*journalValue));
	Check("all-other-target-survives-round-trip",
		decoded
		&& decoded->accounts.front().remoteSessionTarget
			== RemoteSessionTargetKind::AllOtherSessions);
	auto f = Fixtures();
	f.journal = *journalValue;
	const auto report = f.start();
	Check("injected-adapter-receives-server-side-all-other-scope",
		report.result == CoordinatorResult::Complete
		&& f.remote.calls == 1
		&& f.remote.remoteTargets.front()
			== RemoteSessionTargetKind::AllOtherSessions
		&& f.remote.targets.front().empty());

	auto noKnownSessionsPlan = Plan(1);
	noKnownSessionsPlan.accounts.front().remoteTarget
		= RemoteSessionTargetKind::AllOtherSessions;
	noKnownSessionsPlan.accounts.front().sessionIdsForRevokeRequest.clear();
	auto noKnownSessions = MakeJournal(noKnownSessionsPlan);
	Check("all-other-still-runs-with-zero-known-sessions",
		noKnownSessions
		&& noKnownSessions->accounts.front().remoteSessionRevoke.state
			== EffectState::Pending
		&& noKnownSessions->accounts.front().sessionIdsForRevoke.empty());
	if (noKnownSessions) {
		auto empty = Fixtures();
		empty.journal = *noKnownSessions;
		const auto emptyReport = empty.start();
		Check("zero-known-session-adapter-still-gets-all-other",
			emptyReport.result == CoordinatorResult::Complete
			&& empty.remote.calls == 1
			&& empty.remote.remoteTargets.front()
				== RemoteSessionTargetKind::AllOtherSessions
			&& empty.remote.targets.front().empty());
	}
	auto manyKnownSessionsPlan = Plan(1);
	manyKnownSessionsPlan.accounts.front().remoteTarget
		= RemoteSessionTargetKind::AllOtherSessions;
	for (auto i = 0; i != 129; ++i) {
		manyKnownSessionsPlan.accounts.front().sessionIdsForRevokeRequest.push_back(
			SessionId("known-" + std::to_string(i)));
	}
	const auto manyKnownSessions = MakeJournal(manyKnownSessionsPlan);
	Check("all-other-does-not-freeze-or-limit-live-snapshot-ids",
		manyKnownSessions
		&& manyKnownSessions->accounts.front().remoteSessionTarget
			== RemoteSessionTargetKind::AllOtherSessions
		&& manyKnownSessions->accounts.front().sessionIdsForRevoke.empty());
}

void OneFiveSecondBudgetIsSharedAcrossAccounts() {
	auto f = Fixtures();
	f.remote.advanceAfterFirstCall = std::chrono::seconds(6);
	const auto report = f.start();
	Check("expired-shared-budget-skips-later-remote-call",
		report.remoteDeadlineReached
		&& f.remote.calls == 1
		&& f.local.calls.size() == 2);
	Check("unattempted-target-is-skipped-before-local-cleanup",
		f.journal.accounts[1].remoteSessionRevoke.state == EffectState::Skipped
		&& f.journal.accounts[1].remoteSessionRevoke.networkOutcome
			== NetworkOutcome::NotAttempted);
	Check("local-clear-prevents-a-late-remote-retry",
		BeginEffect(
			f.journal,
			JournalEffect::RemoteSessionRevoke,
			AccountId("account-b")) == TransitionResult::Rejected);
	Check("deadline-leaves-a-partial-result",
		report.result == CoordinatorResult::Partial
		&& report.journalStatus == JournalStatus::NeedsAttention);
}

void UnconfirmedRemoteResultDoesNotBlockLocalCleanup() {
	auto f = Fixtures();
	f.remote.results["account-a"] = EffectResult::Unconfirmed;
	const auto report = f.start();
	Check("unconfirmed-remains-unconfirmed-after-cleanup",
		f.journal.accounts[0].remoteSessionRevoke.networkOutcome
			== NetworkOutcome::Unconfirmed
		&& f.journal.accounts[0].localDataClear.state == EffectState::Succeeded);
	Check("safe-destination-follows-successful-local-clears",
		report.safeDestinationAttempted
		&& f.destination.calls == 1
		&& f.events.back() == "destination");
	Check("remote-is-never-retried-after-local-clear",
		BeginEffect(
			f.journal,
			JournalEffect::RemoteSessionRevoke,
			AccountId("account-a")) == TransitionResult::Rejected);
	Check("report-does-not-claim-full-success",
		report.result == CoordinatorResult::Partial
		&& report.journalStatus == JournalStatus::NeedsAttention
		&& report.localCleanupComplete
		&& report.safeDestinationReady);
}

void FailedClaimDoesNotCallAnEffect() {
	auto f = Fixtures();
	f.store.failWrite = 1;
	const auto report = f.start();
	Check("claim-write-failure-stops-before-side-effect",
		report.result == CoordinatorResult::CheckpointFailed
		&& f.remote.calls == 0
		&& f.local.calls.empty()
		&& f.destination.calls == 0
		&& f.journal.accounts[0].remoteSessionRevoke.state == EffectState::Pending);
}

void LostOutcomeCheckpointRecoversAsUnconfirmed() {
	auto f = Fixtures();
	f.store.failWrite = 2;
	const auto first = f.start();
	Check("outcome-save-failure-stops-before-next-effect",
		first.result == CoordinatorResult::CheckpointFailed
		&& f.remote.calls == 1
		&& f.local.calls.empty());
	f.store.failWrite = 0;
	auto recovered = LoadJournal(f.store, OperationId("op-coordinator"));
	if (!recovered) {
		Check("persisted-claim-is-recoverable", false);
		return;
	}
	const auto lease = f.store.tryAcquireExecution();
	const auto second = ResumeResetCoordinator(
		*recovered,
		*lease,
		f.local,
		f.destination);
	Check("persisted-in-flight-network-claim-becomes-unknown",
		std::ranges::count(f.remote.calledAccountIds, "account-a") == 1
		&& recovered->accounts[0].remoteSessionRevoke.networkOutcome
			== NetworkOutcome::Unconfirmed);
	Check("recovery-continues-local-work-without-duplicate-network-call",
		f.local.calls.size() == 2
		&& f.remote.calls == 1
		&& recovered->accounts[1].remoteSessionRevoke.state == EffectState::Skipped
		&& second.result == CoordinatorResult::Partial);
}

void LostLocalOutcomeCanBeRetriedOffline() {
	auto f = Fixtures();
	f.journal = MakeJournal(Plan(1)).value();
	f.store.failWrite = 4;
	const auto first = f.start();
	Check("uncheckpointed-local-success-is-not-reported-as-complete",
		first.result == CoordinatorResult::CheckpointFailed
		&& !first.localCleanupComplete && !first.safeDestinationReady
		&& f.local.calls.size() == 1 && f.destination.calls == 0);
	const auto lease = f.store.tryAcquireExecution();
	const auto online = RunResetCoordinator(
		f.journal, *lease, f.remote, f.local, f.destination, f.clock);
	Check("progressed-journal-cannot-reopen-the-remote-phase",
		online.result == CoordinatorResult::Rejected && f.remote.calls == 1);
	const auto offline = ResumeResetCoordinator(f.journal, *lease, f.local, f.destination);
	Check("interrupted-local-claim-retries-with-confirmed-remote-result-preserved",
		offline.result == CoordinatorResult::Complete
		&& offline.localCleanupComplete && offline.safeDestinationReady
		&& f.remote.calls == 1 && f.local.calls.size() == 2 && f.destination.calls == 1);
}

} // namespace

int main() {
	RemoteClaimsAndSharedDeadlinePrecedeLocalEffects();
	AllOtherSessionsRemainsAServerScope();
	OneFiveSecondBudgetIsSharedAcrossAccounts();
	UnconfirmedRemoteResultDoesNotBlockLocalCleanup();
	FailedClaimDoesNotCallAnEffect();
	LostOutcomeCheckpointRecoversAsUnconfirmed();
	LostLocalOutcomeCanBeRetriedOffline();
	return failures ? 1 : 0;
}
