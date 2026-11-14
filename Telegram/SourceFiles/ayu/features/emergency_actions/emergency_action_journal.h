// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_plan.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Ayu::EmergencyActions {

enum class EffectState : uint8_t {
	NotRequested,
	Pending,
	InProgress,
	Succeeded,
	FailedRetryable,
	Unconfirmed,
};

enum class NetworkOutcome : uint8_t {
	NotAttempted,
	SuccessConfirmed,
	FailureConfirmed,
	Unconfirmed,
};

enum class JournalStatus : uint8_t {
	Ready,
	InProgress,
	NeedsAttention,
	Complete,
};

enum class JournalEffect : uint8_t {
	LocalDataClear,
	RemoteSessionRevoke,
	InstallationRemoval,
	SafeDestinationActivation,
};

enum class EffectResult : uint8_t {
	ConfirmedSuccess,
	ConfirmedFailure,
	Unconfirmed,
};

enum class RetryMode : uint8_t {
	SafeOnly,
	ExplicitlyRetryUnconfirmed,
};

enum class TransitionResult : uint8_t {
	Applied,
	AlreadyApplied,
	Rejected,
};

enum class JournalCreateResult : uint8_t {
	Created,
	AlreadyExists,
	Failed,
};

struct JournalEffectState final {
	EffectState state = EffectState::NotRequested;
	NetworkOutcome networkOutcome = NetworkOutcome::NotAttempted;
	friend bool operator==(const JournalEffectState &, const JournalEffectState &) = default;
};

struct JournalAccount final {
	AccountId accountId;
	JournalEffectState localDataClear;
	RemoteSessionTargetKind remoteSessionTarget = RemoteSessionTargetKind::None;
	JournalEffectState remoteSessionRevoke;
	std::vector<SessionId> sessionIdsForRevoke;
};

struct EmergencyActionJournal final {
	OperationId operationId;
	RuleId ruleId;
	InstallationId installationId;
	EmergencyAction action = EmergencyAction::ResetAccountData;
	TargetScope targetScope = TargetScope::SelectedAccounts;
	std::vector<JournalAccount> accounts;
	JournalEffectState installationRemoval;
	JournalEffectState safeDestinationActivation;
	SafeDestinationKind safeDestination = SafeDestinationKind::None;
	ProfileId safeProfileId;
};

struct PendingEffect final {
	std::optional<AccountId> accountId;
	JournalEffect effect = JournalEffect::LocalDataClear;
};

[[nodiscard]] std::optional<EmergencyActionJournal> MakeJournal(
	const DryRunPlan &plan);

[[nodiscard]] JournalStatus Status(const EmergencyActionJournal &journal);

[[nodiscard]] std::vector<PendingEffect> ResumeEffects(
	const EmergencyActionJournal &journal,
	RetryMode retryMode = RetryMode::SafeOnly);

[[nodiscard]] size_t RecoverInterruptedEffects(
	EmergencyActionJournal &journal);

// This state model is fixture-only and does not authorize or order execution.
[[nodiscard]] TransitionResult BeginEffect(
	EmergencyActionJournal &journal,
	JournalEffect effect,
	std::optional<AccountId> accountId = std::nullopt,
	RetryMode retryMode = RetryMode::SafeOnly);

[[nodiscard]] TransitionResult ResolveEffect(
	EmergencyActionJournal &journal,
	JournalEffect effect,
	EffectResult result,
	std::optional<AccountId> accountId = std::nullopt);

inline constexpr auto kMaxJournalBytes = size_t(1024 * 1024);

[[nodiscard]] std::vector<std::byte> EncodeJournal(
	const EmergencyActionJournal &journal);

[[nodiscard]] std::optional<EmergencyActionJournal> DecodeJournal(
	std::span<const std::byte> bytes);

class JournalStore {
public:
	virtual ~JournalStore() = default;
	// Creates the operation slot atomically without replacing an existing one.
	[[nodiscard]] virtual JournalCreateResult createAtomically(
		const OperationId &operationId,
		std::span<const std::byte> bytes) = 0;
	[[nodiscard]] virtual std::vector<std::byte> read(
		const OperationId &operationId,
		size_t maximumBytes) = 0;
	[[nodiscard]] virtual bool writeAtomically(
		const OperationId &operationId,
		std::span<const std::byte> bytes) = 0;
};

[[nodiscard]] bool SaveJournal(
	JournalStore &store,
	const EmergencyActionJournal &journal);

[[nodiscard]] std::optional<EmergencyActionJournal> LoadJournal(
	JournalStore &store,
	const OperationId &operationId);

} // namespace Ayu::EmergencyActions
