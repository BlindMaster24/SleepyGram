#include "ayu/features/emergency_actions/emergency_action_runtime_service.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

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
	std::map<std::string, std::vector<std::byte>> values;
	int creates = 0;
	int seedWrites = 0;
	int writes = 0;
	bool failCreate = false;

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
};

struct FakeLocal final : LocalAccountEffect {
	explicit FakeLocal(FixtureStore *store) : store(store) {
	}

	FixtureStore *store = nullptr;
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
		return EffectResult::ConfirmedSuccess;
	}
};

struct FakeDestination final : SafeDestinationEffect {
	explicit FakeDestination(FixtureStore *store) : store(store) {
	}

	FixtureStore *store = nullptr;
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
	Check("changed-live-targets-require-new-explicit-review",
		stale.status == RuntimeServiceStatus::StaleReview
		&& f.store.seedWrites == 0 && f.remote.calls == 0
		&& f.local.calls == 0 && f.destination.calls == 0);
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
	f.store.failCreate = true;
	const auto result = f.service.Submit(LockScreenSubmit(), Verifier(0x20));
	Check("journal-must-be-created-before-any-effect", result.status
		== RuntimeServiceStatus::CheckpointFailed
		&& f.remote.calls == 0 && f.local.calls == 0
		&& f.destination.calls == 0);
}

} // namespace

int main() {
	ConfigureReviewAndColdSubmitRunOnce();
	NonLockScreenAndStaleReviewCannotStartEffects();
	FailedFirstJournalWriteStartsNoEffects();
	return failures ? 1 : 0;
}
