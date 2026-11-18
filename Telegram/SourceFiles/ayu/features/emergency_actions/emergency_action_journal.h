// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_plan.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
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
	Skipped,
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
	const EmergencyActionJournal &journal);

[[nodiscard]] size_t RecoverInterruptedEffects(
	EmergencyActionJournal &journal);

[[nodiscard]] bool FinishRemotePhase(EmergencyActionJournal &journal);

[[nodiscard]] bool LocalCleanupComplete(const EmergencyActionJournal &journal);

[[nodiscard]] TransitionResult BeginEffect(
	EmergencyActionJournal &journal,
	JournalEffect effect,
	std::optional<AccountId> accountId = std::nullopt);

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
	class ExecutionLease {
	public:
		virtual ~ExecutionLease() = default;
		ExecutionLease(const ExecutionLease &) = delete;
		ExecutionLease &operator=(const ExecutionLease &) = delete;

		[[nodiscard]] JournalStore &store() const {
			return _store;
		}

	protected:
		explicit ExecutionLease(JournalStore &store) : _store(store) {
		}

	private:
		JournalStore &_store;

	};

	virtual ~JournalStore() = default;
	[[nodiscard]] virtual std::unique_ptr<ExecutionLease> tryAcquireExecution() = 0;
	[[nodiscard]] virtual std::optional<std::vector<OperationId>> operationIds() = 0;
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

class FileJournalStore final : public JournalStore {
public:
	explicit FileJournalStore(std::filesystem::path directory);

	[[nodiscard]] std::unique_ptr<ExecutionLease> tryAcquireExecution() override;
	[[nodiscard]] std::optional<std::vector<OperationId>> operationIds() override;
	[[nodiscard]] JournalCreateResult createAtomically(
		const OperationId &operationId,
		std::span<const std::byte> bytes) override;
	[[nodiscard]] std::vector<std::byte> read(
		const OperationId &operationId,
		size_t maximumBytes) override;
	[[nodiscard]] bool writeAtomically(
		const OperationId &operationId,
		std::span<const std::byte> bytes) override;

private:
	const std::filesystem::path _directory;

};

[[nodiscard]] bool SaveJournal(
	JournalStore &store,
	const EmergencyActionJournal &journal);

[[nodiscard]] std::optional<EmergencyActionJournal> LoadJournal(
	JournalStore &store,
	const OperationId &operationId);

} // namespace Ayu::EmergencyActions
