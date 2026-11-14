// This is the source code of AyuGram for Desktop.
#pragma once

#include <compare>
#include <string>
#include <utility>
#include <vector>

namespace Ayu::EmergencyActions {

template <typename Tag>
struct StableId final {
	std::string value;

	StableId() = default;
	explicit StableId(std::string value) : value(std::move(value)) {
	}

	[[nodiscard]] bool valid() const {
		return !value.empty();
	}

	auto operator<=>(const StableId &) const = default;
};

struct OperationIdTag;
struct RuleIdTag;
struct InstallationIdTag;
struct ProfileIdTag;
struct AccountIdTag;
struct SessionIdTag;
using OperationId = StableId<OperationIdTag>;
using RuleId = StableId<RuleIdTag>;
using InstallationId = StableId<InstallationIdTag>;
using ProfileId = StableId<ProfileIdTag>;
using AccountId = StableId<AccountIdTag>;
using SessionId = StableId<SessionIdTag>;

enum class EmergencyAction {
	ResetAccountData,
	RemoveInstallation,
};

enum class TargetScope {
	SelectedAccounts,
	AllAccounts,
	CurrentInstallation,
};

enum class RemoteSessionTargetKind {
	None,
	SelectedSessions,
	AllOtherSessions,
};

enum class DryRunStatus {
	Ready,
	Rejected,
};

enum class SafeDestinationKind {
	None,
	Profile,
	AddAccount,
};

enum class PlanIssue {
	InvalidOperationId,
	InvalidRuleId,
	InvalidInstallationId,
	InvalidTargetAction,
	EmptySelectedAccounts,
	InvalidConfiguredId,
	DuplicateConfiguredId,
	InvalidRemoteSessionPolicy,
	InvalidLiveSnapshot,
	CurrentSessionCannotBeRemoteTarget,
	SafeProfileContainsAffectedAccount,
};

enum class PlanNotice {
	SelectedAccountNotLive,
	RemotePolicyDefaultsToNone,
	SelectedRemoteSessionNotLive,
	SafeProfileUnavailable,
};

struct RemoteSessionPolicy final {
	AccountId accountId;
	RemoteSessionTargetKind kind = RemoteSessionTargetKind::None;
	std::vector<SessionId> selectedSessionIds;
};

struct EmergencyRule final {
	RuleId id;
	InstallationId installationId;
	EmergencyAction action = EmergencyAction::ResetAccountData;
	TargetScope targetScope = TargetScope::SelectedAccounts;
	std::vector<AccountId> selectedAccountIds;
	std::vector<RemoteSessionPolicy> remoteSessionPolicies;
	ProfileId safeProfileId;
};

struct LiveAccount final {
	AccountId id;
	SessionId currentSessionId;
	std::vector<SessionId> sessionIds;
};

struct LiveProfile final {
	ProfileId id;
	std::vector<AccountId> accountIds;
};

struct LiveInstallation final {
	InstallationId id;
	std::vector<LiveAccount> accounts;
	std::vector<LiveProfile> profiles;
};

struct AccountDryRun final {
	AccountId accountId;
	bool wouldClearLocalData = true;
	RemoteSessionTargetKind remoteTarget = RemoteSessionTargetKind::None;
	bool remoteTargetWasConfigured = false;
	std::vector<SessionId> sessionIdsForRevokeRequest;
	std::vector<SessionId> selectedSessionIdsNotLive;
};

struct DryRunPlan final {
	// All "would" fields describe a simulation. Building this value never
	// executes a local or remote operation.
	OperationId operationId;
	RuleId ruleId;
	InstallationId installationId;
	EmergencyAction action = EmergencyAction::ResetAccountData;
	TargetScope targetScope = TargetScope::SelectedAccounts;
	DryRunStatus status = DryRunStatus::Ready;
	std::vector<PlanIssue> issues;
	std::vector<PlanNotice> notices;
	std::vector<AccountId> selectedAccountIdsNotLive;
	std::vector<AccountDryRun> accounts;
	SafeDestinationKind safeDestination = SafeDestinationKind::None;
	ProfileId safeProfileId;
	std::vector<AccountId> safeProfileAccountIds;
	bool wouldRemoveInstallation = false;
};

// Resolves every target against this invocation's live snapshot. Callers must
// rebuild immediately before any future invocation; a saved plan is not a
// durable target list.
[[nodiscard]] DryRunPlan BuildDryRunPlan(
	OperationId operationId,
	const EmergencyRule &rule,
	const LiveInstallation &live);

} // namespace Ayu::EmergencyActions
