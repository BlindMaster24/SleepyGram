#include "ayu/features/emergency_actions/emergency_action_journal.h"

#include <algorithm>
#include <array>
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

DryRunPlan Plan() {
	return {
		.operationId = OperationId("op-1"),
		.ruleId = RuleId("rule-1"),
		.installationId = InstallationId("install-1"),
		.action = EmergencyAction::ResetAccountData,
		.targetScope = TargetScope::SelectedAccounts,
		.accounts = {
			{
				.accountId = AccountId("account-a"),
				.wouldClearLocalData = true,
				.remoteTarget = RemoteSessionTargetKind::SelectedSessions,
				.remoteTargetWasConfigured = true,
				.sessionIdsForRevokeRequest = {
					SessionId("session-b"),
					SessionId("session-a"),
				},
			},
		},
		.safeDestination = SafeDestinationKind::Profile,
		.safeProfileId = ProfileId("safe-profile"),
	};
}

struct FixtureStore final : JournalStore {
	std::map<std::string, std::vector<std::byte>> values;
	bool failNextWrite = false;
	int writes = 0;

	std::unique_ptr<ExecutionLease> tryAcquireExecution() override {
		return nullptr;
	}

	std::optional<std::vector<OperationId>> operationIds() override {
		auto ids = std::vector<OperationId>();
		for (const auto &[id, bytes] : values) {
			ids.emplace_back(id);
		}
		return ids;
	}

	JournalCreateResult createAtomically(
			const OperationId &operationId,
			std::span<const std::byte> bytes) override {
		if (values.contains(operationId.value)) {
			return JournalCreateResult::AlreadyExists;
		}
		if (failNextWrite) {
			failNextWrite = false;
			return JournalCreateResult::Failed;
		}
		values.emplace(
			operationId.value,
			std::vector<std::byte>(bytes.begin(), bytes.end()));
		return JournalCreateResult::Created;
	}

	std::vector<std::byte> read(
			const OperationId &operationId,
			size_t maximumBytes) override {
		const auto i = values.find(operationId.value);
		if (i == values.end() || i->second.size() > maximumBytes) {
			return {};
		}
		return i->second;
	}

	bool writeAtomically(
			const OperationId &operationId,
			std::span<const std::byte> bytes) override {
		++writes;
		if (failNextWrite) {
			failNextWrite = false;
			return false;
		}
		auto temporary = std::vector<std::byte>(bytes.begin(), bytes.end());
		values[operationId.value].swap(temporary);
		return true;
	}
};

bool HasEffect(
		const std::vector<PendingEffect> &effects,
		JournalEffect effect,
		const std::optional<AccountId> &accountId = std::nullopt) {
	return std::ranges::any_of(effects, [&](const PendingEffect &candidate) {
		return candidate.effect == effect && candidate.accountId == accountId;
	});
}

void DurableJournalRoundTripsExactPlanTargets() {
	const auto source = MakeJournal(Plan());
	Check("valid-plan-creates-journal", bool(source));
	if (!source) return;
	const auto bytes = EncodeJournal(*source);
	const auto decoded = DecodeJournal(bytes);
	Check("versioned-journal-round-trips-canonically",
		decoded
		&& EncodeJournal(*decoded) == bytes
		&& decoded->operationId == OperationId("op-1")
		&& decoded->targetScope == TargetScope::SelectedAccounts
		&& decoded->accounts.size() == 1
		&& decoded->accounts.front().accountId == AccountId("account-a")
		&& decoded->accounts.front().remoteSessionTarget
			== RemoteSessionTargetKind::SelectedSessions
		&& decoded->accounts.front().sessionIdsForRevoke
			== std::vector<SessionId>{ SessionId("session-a"), SessionId("session-b") });
	Check("initial-resume-list-has-only-planned-effects",
		HasEffect(ResumeEffects(*source), JournalEffect::LocalDataClear,
			AccountId("account-a"))
		&& HasEffect(ResumeEffects(*source), JournalEffect::RemoteSessionRevoke,
			AccountId("account-a"))
		&& !HasEffect(ResumeEffects(*source), JournalEffect::SafeDestinationActivation));
}

void NetworkUnknownCannotBeRetried() {
	auto journal = MakeJournal(Plan()).value();
	Check("remote-starts-once", BeginEffect(
		journal,
		JournalEffect::RemoteSessionRevoke,
		AccountId("account-a")) == TransitionResult::Applied);
	Check("duplicate-start-does-not-repeat-effect", BeginEffect(
		journal,
		JournalEffect::RemoteSessionRevoke,
		AccountId("account-a")) == TransitionResult::AlreadyApplied);
	Check("unconfirmed-network-outcome-is-preserved", ResolveEffect(
		journal,
		JournalEffect::RemoteSessionRevoke,
		EffectResult::Unconfirmed,
		AccountId("account-a")) == TransitionResult::Applied
		&& journal.accounts.front().remoteSessionRevoke.state == EffectState::Unconfirmed
		&& journal.accounts.front().remoteSessionRevoke.networkOutcome
			== NetworkOutcome::Unconfirmed);
	Check("unknown-outcome-needs-attention-and-is-not-auto-retried",
		Status(journal) == JournalStatus::NeedsAttention
		&& !HasEffect(ResumeEffects(journal), JournalEffect::RemoteSessionRevoke,
			AccountId("account-a")));
	Check("unknown-outcome-cannot-restart", BeginEffect(
		journal,
		JournalEffect::RemoteSessionRevoke,
		AccountId("account-a")) == TransitionResult::Rejected);
	journal = MakeJournal(Plan()).value();
	Check("fresh-attempt-records-confirmed-network-success", BeginEffect(
		journal,
		JournalEffect::RemoteSessionRevoke,
		AccountId("account-a")) == TransitionResult::Applied
		&& ResolveEffect(
			journal,
			JournalEffect::RemoteSessionRevoke,
			EffectResult::ConfirmedSuccess,
			AccountId("account-a")) == TransitionResult::Applied
		&& journal.accounts.front().remoteSessionRevoke.networkOutcome
			== NetworkOutcome::SuccessConfirmed);
}

void RecoveryAndLocalTransitionsAreIdempotent() {
	auto journal = MakeJournal(Plan()).value();
	Check("local-clear-starts", BeginEffect(
		journal,
		JournalEffect::LocalDataClear,
		AccountId("account-a")) == TransitionResult::Applied);
	Check("interrupted-local-effect-recovers-as-retryable",
		RecoverInterruptedEffects(journal) == 1
		&& RecoverInterruptedEffects(journal) == 0
		&& journal.accounts.front().localDataClear.state == EffectState::FailedRetryable);
	Check("recovered-local-effect-can-be-retried-offline",
		HasEffect(ResumeEffects(journal), JournalEffect::LocalDataClear,
			AccountId("account-a")));
	Check("local-clear-retry-and-completion",
		BeginEffect(
			journal,
			JournalEffect::LocalDataClear,
			AccountId("account-a")) == TransitionResult::Applied
		&& ResolveEffect(
			journal,
			JournalEffect::LocalDataClear,
			EffectResult::ConfirmedSuccess,
			AccountId("account-a")) == TransitionResult::Applied);
	Check("repeating-completed-result-is-idempotent", ResolveEffect(
		journal,
		JournalEffect::LocalDataClear,
		EffectResult::ConfirmedSuccess,
		AccountId("account-a")) == TransitionResult::AlreadyApplied);
	Check("destination-is-eligible-after-durable-local-cleanup",
		HasEffect(ResumeEffects(journal), JournalEffect::SafeDestinationActivation));
}

void CodecRejectsMalformedAndFutureData() {
	const auto bytes = EncodeJournal(MakeJournal(Plan()).value());
	auto truncated = bytes;
	truncated.pop_back();
	Check("truncated-journal-rejected", !DecodeJournal(truncated));
	auto future = bytes;
	future[4] = std::byte(255);
	Check("unknown-version-rejected", !DecodeJournal(future));
	Check("oversized-journal-rejected",
		!DecodeJournal(std::vector<std::byte>(kMaxJournalBytes + 1)));
	auto trailing = bytes;
	trailing.push_back(std::byte(0));
	Check("trailing-data-rejected", !DecodeJournal(trailing));
	auto invalidId = MakeJournal(Plan()).value();
	invalidId.accounts.front().accountId.value = "account/secret";
	Check("invalid-id-and-free-text-rejected", EncodeJournal(invalidId).empty());
}

void LegacyJournalDecodesToExactFrozenSessionTargets() {
	auto bytes = std::vector<std::byte>();
	const auto byte = [&](uint8_t value) {
		bytes.push_back(std::byte(value));
	};
	const auto u16 = [&](uint16_t value) {
		byte(uint8_t(value));
		byte(uint8_t(value >> 8));
	};
	const auto string = [&](const std::string &value) {
		u16(uint16_t(value.size()));
		for (const auto ch : value) byte(uint8_t(ch));
	};
	const auto state = [&](uint8_t value) {
		byte(value);
		byte(uint8_t(NetworkOutcome::NotAttempted));
	};
	for (const auto ch : std::array<uint8_t, 4>{ 'A', 'E', 'J', '1' }) byte(ch);
	u16(1);
	string("legacy-op");
	string("legacy-rule");
	string("legacy-install");
	byte(uint8_t(EmergencyAction::ResetAccountData));
	byte(uint8_t(TargetScope::SelectedAccounts));
	byte(uint8_t(SafeDestinationKind::None));
	string("");
	u16(1);
	string("account-a");
	state(uint8_t(EffectState::Pending));
	state(uint8_t(EffectState::Pending));
	u16(1);
	string("session-a");
	state(uint8_t(EffectState::NotRequested));
	state(uint8_t(EffectState::NotRequested));
	const auto decoded = DecodeJournal(bytes);
	Check("legacy-v1-keeps-its-frozen-exact-targets",
		decoded
		&& decoded->accounts.size() == 1
		&& decoded->accounts.front().remoteSessionTarget
			== RemoteSessionTargetKind::SelectedSessions
		&& decoded->accounts.front().sessionIdsForRevoke
			== std::vector<SessionId>{ SessionId("session-a") });
}

void StoreUsesAtomicStorageBoundary() {
	auto journal = MakeJournal(Plan()).value();
	auto store = FixtureStore();
	Check("save-and-load-use-storage-abstraction",
		SaveJournal(store, journal)
		&& LoadJournal(store, journal.operationId).has_value()
		&& store.writes == 1);
	const auto previous = store.values.at(journal.operationId.value);
	store.failNextWrite = true;
	journal.accounts.front().localDataClear.state = EffectState::InProgress;
	Check("failed-atomic-save-preserves-old-journal",
		!SaveJournal(store, journal)
		&& store.values.at(journal.operationId.value) == previous);
	Check("load-enforces-operation-key-binding",
		!LoadJournal(store, OperationId("another-operation")));
}

} // namespace

int main() {
	DurableJournalRoundTripsExactPlanTargets();
	NetworkUnknownCannotBeRetried();
	RecoveryAndLocalTransitionsAreIdempotent();
	CodecRejectsMalformedAndFutureData();
	LegacyJournalDecodesToExactFrozenSessionTargets();
	StoreUsesAtomicStorageBoundary();
	return failures ? 1 : 0;
}
