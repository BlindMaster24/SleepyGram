#include "ayu/features/emergency_actions/emergency_action_runtime_service.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#ifndef _WIN32
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

using namespace Ayu::EmergencyActions;

int failures = 0;

void Check(const char *name, bool condition) {
	std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
	failures += !condition;
}

CredentialVerifier Verifier(uint8_t tag) {
	auto result = CredentialVerifier();
	result[0] = tag;
	result.back() = uint8_t(tag ^ 0xA5);
	return result;
}

EmergencyRule Rule() {
	return {
		.id = RuleId("rule-runtime"),
		.installationId = InstallationId("install-runtime"),
		.action = EmergencyAction::ResetAccountData,
		.targetScope = TargetScope::SelectedAccounts,
		.selectedAccountIds = { AccountId("account-runtime") },
		.remoteSessionPolicies = {
			{
				.accountId = AccountId("account-runtime"),
				.kind = RemoteSessionTargetKind::AllOtherSessions,
			},
		},
		.safeProfileId = ProfileId("safe-profile"),
	};
}

LiveInstallation Live() {
	return {
		.id = InstallationId("install-runtime"),
		.accounts = {
			{
				.id = AccountId("account-runtime"),
				.currentSessionId = SessionId("current-session"),
				.sessionIds = {
					SessionId("current-session"),
					SessionId("other-session"),
				},
			},
		},
		.profiles = {
			{ .id = ProfileId("safe-profile"), .accountIds = {} },
		},
	};
}

RuleConfiguration Configuration() {
	return {
		.activeInstallationId = InstallationId("install-runtime"),
		.masterVerifier = Verifier(0xE0),
		.normalCredentials = {
			{ .id = NormalPasscodeId("normal-set"), .verifier = Verifier(0x10) },
		},
		.emergencyRules = {
			{
				.id = EmergencyActionId("action-runtime"),
				.rule = Rule(),
				.verifier = Verifier(0x20),
				.revision = 1,
			},
		},
	};
}

struct FixtureStore final : JournalStore {
	struct Lease final : ExecutionLease {
		explicit Lease(JournalStore &store) : ExecutionLease(store) {
		}
	};

	std::map<std::string, std::vector<std::byte>> values;
	int creates = 0;
	int seedWrites = 0;
	int writes = 0;
	bool failCreate = false;
	bool executionBusy = false;

	std::unique_ptr<ExecutionLease> tryAcquireExecution() override {
		return executionBusy ? nullptr : std::make_unique<Lease>(*this);
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
		++creates;
		if (values.contains(id.value)) return JournalCreateResult::AlreadyExists;
		if (failCreate) return JournalCreateResult::Failed;
		values.emplace(id.value, std::vector<std::byte>(bytes.begin(), bytes.end()));
		++seedWrites;
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
		values[id.value] = std::vector<std::byte>(bytes.begin(), bytes.end());
		return true;
	}
};

struct FakeClock final : CoordinatorClock {
	TimePoint now() const override {
		return {};
	}
};

struct FakeRemote final : RemoteSessionEffect {
	explicit FakeRemote(FixtureStore *store) : store(store) {
	}

	FixtureStore *store = nullptr;
	int calls = 0;
	bool claimWasDurable = false;
	RemoteSessionTargetKind target = RemoteSessionTargetKind::None;
	std::vector<SessionId> sessions;

	EffectResult revoke(
			const AccountId &accountId,
			RemoteSessionTargetKind requestedTarget,
			std::span<const SessionId> sessionIds,
			CoordinatorClock::TimePoint) override {
		++calls;
		target = requestedTarget;
		sessions.assign(sessionIds.begin(), sessionIds.end());
		const auto saved = LoadJournal(*store, OperationId("operation-reviewed"));
		claimWasDurable = saved && std::ranges::any_of(
			saved->accounts,
			[&](const JournalAccount &account) {
				return account.accountId == accountId
					&& account.remoteSessionRevoke.state == EffectState::InProgress;
			});
		return EffectResult::ConfirmedSuccess;
	}

	EffectResult logoutCurrent(
			const AccountId &accountId,
			CoordinatorClock::TimePoint) override {
		const auto saved = LoadJournal(*store, OperationId("operation-reviewed"));
		return (saved && std::ranges::any_of(
			saved->accounts,
			[&](const JournalAccount &account) {
				return account.accountId == accountId
					&& account.currentSessionLogout.state == EffectState::InProgress;
			})) ? EffectResult::ConfirmedSuccess : EffectResult::Unconfirmed;
	}
};

struct FakeLocal final : LocalAccountEffect {
	explicit FakeLocal(JournalStore *store) : store(store) {
	}

	JournalStore *store = nullptr;
	EffectResult outcome = EffectResult::ConfirmedSuccess;
	int calls = 0;
	bool claimWasDurable = false;

	EffectResult clear(const AccountId &accountId) override {
		++calls;
		const auto saved = LoadJournal(*store, OperationId("operation-reviewed"));
		claimWasDurable = saved && std::ranges::any_of(
			saved->accounts,
			[&](const JournalAccount &account) {
				return account.accountId == accountId
					&& account.localDataClear.state == EffectState::InProgress;
			});
		return outcome;
	}
};

struct FakeDestination final : SafeDestinationEffect {
	explicit FakeDestination(JournalStore *store) : store(store) {
	}

	JournalStore *store = nullptr;
	int calls = 0;
	bool claimWasDurable = false;

	EffectResult activate(
			SafeDestinationKind kind,
			const ProfileId &profileId) override {
		++calls;
		const auto saved = LoadJournal(*store, OperationId("operation-reviewed"));
		claimWasDurable = saved
			&& saved->safeDestination == kind
			&& saved->safeProfileId == profileId
			&& saved->safeDestinationActivation.state == EffectState::InProgress;
		return EffectResult::ConfirmedSuccess;
	}
};

struct Fixture final {
	RuleConfiguration config = Configuration();
	LiveInstallation live = Live();
	FixtureStore store;
	FakeClock clock;
	FakeRemote remote{ &store };
	FakeLocal local{ &store };
	FakeDestination destination{ &store };
	EmergencyActionRuntimeService service{
		config,
		[this] { return std::optional<LiveInstallation>(live); },
		store,
		remote,
		local,
		destination,
		clock,
	};
};

void ConfigureReviewAndColdSubmitRunOnce() {
	auto f = Fixture();
	const auto id = EmergencyActionId("action-runtime");
	const auto preview = PreviewEmergencyRule(
		f.config,
		id,
		f.live,
		OperationId("operation-reviewed"));
	Check("user-style-preview-is-ready", preview
		&& preview->plan.status == DryRunStatus::Ready);
	if (!preview) return;
	auto inactive = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("unconfirmed-rule-has-no-effects", inactive.status
		== RuntimeServiceStatus::NoEmergencyMatch
		&& f.store.seedWrites == 0 && f.remote.calls == 0
		&& f.local.calls == 0 && f.destination.calls == 0);
	Check("explicit-review-confirms-current-plan",
		ConfirmEmergencyRule(f.config, *preview, f.live, true));
	auto first = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("cold-submit-reaches-runtime-coordinator", first.status
		== RuntimeServiceStatus::Coordinated && first.coordinator
		&& first.coordinator->result == CoordinatorResult::Complete);
	Check("journal-seeded-once-before-fixture-effects", f.store.seedWrites == 1
		&& f.remote.calls == 1 && f.local.calls == 1 && f.destination.calls == 1
		&& f.remote.claimWasDurable && f.local.claimWasDurable
		&& f.destination.claimWasDurable);
	Check("all-other-sessions-scope-survives-runtime-dispatch",
		f.remote.target == RemoteSessionTargetKind::AllOtherSessions
		&& f.remote.sessions.empty());
	const auto writesAfterCompletion = f.store.writes;
	auto repeated = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("repeat-submit-reuses-complete-operation-without-effects",
		repeated.status == RuntimeServiceStatus::Coordinated
		&& repeated.coordinator
		&& repeated.coordinator->journalStatus == JournalStatus::Complete
		&& f.store.seedWrites == 1 && f.remote.calls == 1
		&& f.local.calls == 1 && f.destination.calls == 1
		&& f.store.writes == writesAfterCompletion);
}

void BindRemoteOnlyToTheDurablyApprovedTargets() {
	auto f = Fixture();
	const auto preview = PreviewEmergencyRule(
		f.config,
		EmergencyActionId("action-runtime"),
		f.live,
		OperationId("operation-reviewed"));
	if (!preview || !ConfirmEmergencyRule(f.config, *preview, f.live, true)) {
		Check("provider-fixture-confirms-rule", false);
		return;
	}
	auto bindings = 0;
	auto matchedSeed = false;
	auto service = EmergencyActionRuntimeService(
		f.config,
		[&] { return std::optional<LiveInstallation>(f.live); },
		f.store,
		[&](const EmergencyActionJournal &approved)
		-> std::unique_ptr<RemoteSessionEffect> {
			++bindings;
			const auto saved = LoadJournal(f.store, approved.operationId);
			matchedSeed = saved && EncodeJournal(*saved) == EncodeJournal(approved);
			return nullptr;
		},
		f.local,
		f.destination,
		f.clock);
	const auto first = service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("remote-provider-receives-durable-frozen-targets",
		bindings == 1 && matchedSeed);
	const auto saved = LoadJournal(f.store, preview->plan.operationId);
	Check("unavailable-remote-provider-does-not-block-local-reset",
		first.coordinator && first.coordinator->safeDestinationReady
		&& f.local.calls == 1 && saved
		&& saved->accounts.front().currentSessionLogout.state == EffectState::Skipped);
	const auto repeated = service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("resuming-never-recreates-remote-provider",
		repeated.coordinator && bindings == 1 && f.local.calls == 1);
}

void NonLockScreenAndStaleReviewCannotStartEffects() {
	auto f = Fixture();
	const auto preview = PreviewEmergencyRule(
		f.config,
		EmergencyActionId("action-runtime"),
		f.live,
		OperationId("operation-reviewed"));
	if (!preview || !ConfirmEmergencyRule(f.config, *preview, f.live, true)) {
		Check("fixture-rule-confirms", false);
		return;
	}
	const auto settings = CheckNonLockScreenPasscode(
		NonLockScreenPurpose::SettingsConfirmation,
		f.config,
		Verifier(0x20));
	Check("settings-check-cannot-return-emergency-action",
		std::holds_alternative<WrongPasscode>(settings)
		&& f.store.seedWrites == 0 && f.remote.calls == 0
		&& f.local.calls == 0 && f.destination.calls == 0);
	f.live.profiles.front().accountIds.push_back(AccountId("account-runtime"));
	const auto stale = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("live-safe-profile-cannot-contain-a-selected-account",
		stale.status == RuntimeServiceStatus::StaleReview
		&& f.store.seedWrites == 0 && f.remote.calls == 0
		&& f.local.calls == 0 && f.destination.calls == 0);
}

LiveAccount AddedAccount() {
	return {
		.id = AccountId("added-later"),
		.currentSessionId = SessionId("added-current"),
		.sessionIds = { SessionId("added-current") },
	};
}

void ResetAllResolvesLiveAccountsOnce() {
	auto f = Fixture();
	auto &rule = f.config.emergencyRules.front().rule;
	rule.targetScope = TargetScope::AllAccounts;
	rule.selectedAccountIds.clear();
	const auto preview = PreviewEmergencyRule(
		f.config,
		EmergencyActionId("action-runtime"),
		f.live,
		OperationId("operation-reviewed"));
	if (!preview || !ConfirmEmergencyRule(f.config, *preview, f.live, true)) {
		Check("reset-all-fixture-confirms", false);
		return;
	}
	f.live.accounts.push_back(AddedAccount());
	f.live.profiles.front().accountIds.push_back(f.live.accounts.back().id);
	const auto unsafe = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("reset-all-revalidates-that-the-safe-profile-is-empty",
		unsafe.status == RuntimeServiceStatus::StaleReview && f.store.seedWrites == 0);
	f.live.profiles.front().accountIds.clear();
	const auto first = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	const auto saved = LoadJournal(f.store, OperationId("operation-reviewed"));
	Check("reset-all-includes-accounts-added-after-review",
		first.status == RuntimeServiceStatus::Coordinated
		&& preview->plan.accounts.size() == 1 && saved && saved->accounts.size() == 2
		&& saved->accounts[0].accountId == AccountId("account-runtime")
		&& saved->accounts[1].accountId == AccountId("added-later")
		&& saved->accounts[1].remoteSessionTarget == RemoteSessionTargetKind::None
		&& f.local.calls == 2 && f.remote.calls == 1);
	f.live = LiveInstallation();
	const auto replay = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("reset-all-replay-uses-frozen-accounts-without-a-live-snapshot",
		replay.status == RuntimeServiceStatus::Coordinated
		&& f.store.seedWrites == 1 && f.local.calls == 2 && f.remote.calls == 1);
}

void SelectedRuleDoesNotWidenOnLiveChanges() {
	auto f = Fixture();
	auto &rule = f.config.emergencyRules.front().rule;
	rule.remoteSessionPolicies.front().kind = RemoteSessionTargetKind::SelectedSessions;
	rule.remoteSessionPolicies.front().selectedSessionIds = { SessionId("other-session") };
	const auto preview = PreviewEmergencyRule(
		f.config,
		EmergencyActionId("action-runtime"),
		f.live,
		OperationId("operation-reviewed"));
	if (!preview || !ConfirmEmergencyRule(f.config, *preview, f.live, true)) {
		Check("selected-rule-fixture-confirms", false);
		return;
	}
	f.live.accounts.push_back(AddedAccount());
	f.live.accounts.front().sessionIds.back() = SessionId("replacement-session");
	rule.selectedAccountIds.push_back(f.live.accounts.back().id);
	const auto changed = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("changed-selected-rule-cannot-use-an-old-confirmation",
		changed.status == RuntimeServiceStatus::NoEmergencyMatch && f.store.seedWrites == 0);
	rule.selectedAccountIds.pop_back();
	const auto first = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	const auto saved = LoadJournal(f.store, OperationId("operation-reviewed"));
	Check("selected-rule-targets-only-confirmed-accounts-and-exact-session-ids",
		first.status == RuntimeServiceStatus::Coordinated
		&& saved && saved->accounts.size() == 1
		&& saved->accounts[0].accountId == AccountId("account-runtime")
		&& saved->accounts[0].sessionIdsForRevoke.empty()
		&& f.local.calls == 1 && f.remote.calls == 0);
	if (saved) {
		auto widened = *saved;
		widened.accounts.front().accountId = AccountId("added-later");
		const auto overwritten = SaveJournal(f.store, widened);
		const auto replay = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
		Check("selected-replay-rejects-a-journal-for-an-unselected-account",
			overwritten && replay.status == RuntimeServiceStatus::Rejected);
	}
}

void FailedFirstJournalWriteStartsNoEffects() {
	auto f = Fixture();
	const auto preview = PreviewEmergencyRule(
		f.config,
		EmergencyActionId("action-runtime"),
		f.live,
		OperationId("operation-reviewed"));
	if (!preview || !ConfirmEmergencyRule(f.config, *preview, f.live, true)) {
		Check("fixture-rule-confirms-for-journal-failure", false);
		return;
	}
	f.store.executionBusy = true;
	const auto busy = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("overlapping-submit-does-not-create-or-run-an-operation",
		busy.status == RuntimeServiceStatus::CheckpointFailed
		&& f.store.creates == 0 && f.remote.calls == 0 && f.local.calls == 0);
	f.store.executionBusy = false;
	f.store.failCreate = true;
	const auto result = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("journal-must-be-created-before-any-effect", result.status
		== RuntimeServiceStatus::CheckpointFailed
		&& f.remote.calls == 0 && f.local.calls == 0
		&& f.destination.calls == 0);
}

class FixtureDirectory final {
public:
	FixtureDirectory()
	: path(std::filesystem::temp_directory_path() / ("sleepygram-journal-test-"
		+ std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())))
	, owned(std::filesystem::create_directory(path)) {
	}

	~FixtureDirectory() {
		if (owned) {
			auto error = std::error_code();
			std::filesystem::remove_all(path, error);
		}
	}

	const std::filesystem::path path;
	const bool owned;
};

void OfflineStartupFinishesLocalCleanupFromDisk() {
	const auto fixtureDirectory = FixtureDirectory();
	if (!fixtureDirectory.owned) {
		Check("temporary-fixture-directory-created", false);
		return;
	}
	const auto plan = BuildDryRunPlan(OperationId("operation-reviewed"), Rule(), Live());
	auto journal = MakeJournal(plan).value();
	const auto path = fixtureDirectory.path / "journal";
	{
		auto store = FileJournalStore(path);
		auto reopened = FileJournalStore(path);
		const auto lease = store.tryAcquireExecution();
		Check("separate-file-stores-share-one-execution-lease",
			lease && !reopened.tryAcquireExecution());
		const auto seed = EncodeJournal(journal);
		Check("native-store-creates-the-slot-without-overwrite",
			store.createAtomically(journal.operationId, seed) == JournalCreateResult::Created
			&& reopened.createAtomically(journal.operationId, seed)
				== JournalCreateResult::AlreadyExists
			&& reopened.read(journal.operationId, seed.size() - 1).empty());
		Check("fixture-persists-an-interrupted-local-stage",
			FinishRemotePhase(journal)
			&& BeginEffect(
				journal,
				JournalEffect::LocalDataClear,
				AccountId("account-runtime")) == TransitionResult::Applied
			&& SaveJournal(store, journal));
	}
	auto store = FileJournalStore(path);
	auto local = FakeLocal(&store);
	auto destination = FakeDestination(&store);
	const auto foreign = ResumePendingResetOperations(
		store, InstallationId("another-installation"), local, destination);
	Check("cold-start-rejects-a-foreign-installation-journal",
		!foreign.canStartAccounts && local.calls == 0 && destination.calls == 0);
	local.outcome = EffectResult::ConfirmedFailure;
	const auto first = ResumePendingResetOperations(store, plan.installationId, local, destination);
	Check("local-cleanup-failure-blocks-account-startup",
		!first.canStartAccounts && local.calls == 1 && local.claimWasDurable
		&& destination.calls == 0);
	local.outcome = EffectResult::ConfirmedSuccess;
	const auto second = ResumePendingResetOperations(store, plan.installationId, local, destination);
	const auto saved = LoadJournal(store, journal.operationId);
	Check("offline-retry-opens-safe-destination-with-remote-still-unconfirmed",
		second.canStartAccounts && second.operations.size() == 1
		&& second.operations[0].result == CoordinatorResult::Partial
		&& second.operations[0].localCleanupComplete
		&& second.operations[0].safeDestinationReady
		&& local.calls == 2 && destination.calls == 1 && destination.claimWasDurable
		&& saved && saved->accounts[0].remoteSessionRevoke.state == EffectState::Skipped
		&& saved->accounts[0].localDataClear.state == EffectState::Succeeded);
	const auto third = ResumePendingResetOperations(store, plan.installationId, local, destination);
	Check("subsequent-startup-does-not-repeat-completed-local-effects",
		third.canStartAccounts && local.calls == 2 && destination.calls == 1);
	std::ofstream(path / "invalid.journal", std::ios::binary) << "truncated";
	const auto corrupt = ResumePendingResetOperations(store, plan.installationId, local, destination);
	Check("corrupt-durable-journal-blocks-account-startup", !corrupt.canStartAccounts);
}

#ifndef _WIN32
void ExecutionLeaseRecoversAfterProcessDeath() {
	const auto directory = FixtureDirectory();
	if (!directory.owned) {
		Check("temporary-lease-fixture-created", false);
		return;
	}
	auto ready = std::array<int, 2>();
	if (pipe(ready.data()) != 0) {
		Check("fixture-pipe-created", false);
		return;
	}
	const auto path = directory.path / "journal";
	const auto plan = BuildDryRunPlan(OperationId("operation-reviewed"), Rule(), Live());
	auto journal = MakeJournal(plan).value();
	const auto child = fork();
	if (child == 0) {
		close(ready[0]);
		auto store = FileJournalStore(path);
		const auto lease = store.tryAcquireExecution();
		const auto readyToInterrupt = char(lease
			&& store.createAtomically(journal.operationId, EncodeJournal(journal))
				== JournalCreateResult::Created
			&& BeginEffect(
				journal,
				JournalEffect::RemoteSessionRevoke,
				AccountId("account-runtime")) == TransitionResult::Applied
			&& SaveJournal(store, journal));
		if (write(ready[1], &readyToInterrupt, 1) != 1 || !readyToInterrupt) {
			_exit(1);
		}
		pause();
		_exit(1);
	}
	close(ready[1]);
	auto locked = char(0);
	const auto running = child > 0 && read(ready[0], &locked, 1) == 1 && locked;
	close(ready[0]);
	auto store = FileJournalStore(path);
	Check("lease-excludes-a-different-process", running && !store.tryAcquireExecution());
	if (child > 0) {
		kill(child, SIGKILL);
		waitpid(child, nullptr, 0);
	}
	Check("lease-is-available-after-process-death", running && store.tryAcquireExecution());
	auto local = FakeLocal(&store);
	auto destination = FakeDestination(&store);
	const auto resumed = ResumePendingResetOperations(store, plan.installationId, local, destination);
	const auto saved = LoadJournal(store, journal.operationId);
	Check("process-death-preserves-remote-ambiguity-and-recovers-offline",
		running && resumed.canStartAccounts && local.calls == 1 && destination.calls == 1
		&& saved && saved->accounts[0].remoteSessionRevoke.state == EffectState::Unconfirmed
		&& saved->accounts[0].remoteSessionRevoke.networkOutcome == NetworkOutcome::Unconfirmed);
}
#endif

} // namespace

int main() {
	ConfigureReviewAndColdSubmitRunOnce();
	BindRemoteOnlyToTheDurablyApprovedTargets();
	NonLockScreenAndStaleReviewCannotStartEffects();
	ResetAllResolvesLiveAccountsOnce();
	SelectedRuleDoesNotWidenOnLiveChanges();
	FailedFirstJournalWriteStartsNoEffects();
	OfflineStartupFinishesLocalCleanupFromDisk();
#ifndef _WIN32
	ExecutionLeaseRecoversAfterProcessDeath();
#endif
	return failures ? 1 : 0;
}
