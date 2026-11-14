#include "ayu/features/emergency_actions/emergency_action_plan.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace {

using namespace Ayu::EmergencyActions;

int failures = 0;

void Check(const char *name, bool condition) {
	std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
	failures += !condition;
}

EmergencyRule BaseRule() {
	return {
		.id = RuleId("rule-1"),
		.installationId = InstallationId("install-1"),
		.action = EmergencyAction::ResetAccountData,
		.targetScope = TargetScope::SelectedAccounts,
		.selectedAccountIds = { AccountId("account-a") },
		.remoteSessionPolicies = {
			{ .accountId = AccountId("account-a") },
		},
		.safeProfileId = ProfileId("safe"),
	};
}

LiveInstallation BaseLive() {
	return {
		.id = InstallationId("install-1"),
		.accounts = {
			{
				.id = AccountId("account-a"),
				.currentSessionId = SessionId("a-current"),
				.sessionIds = { SessionId("a-current"), SessionId("a-other") },
			},
			{
				.id = AccountId("account-b"),
				.currentSessionId = SessionId("b-current"),
				.sessionIds = {
					SessionId("b-current"),
					SessionId("b-1"),
					SessionId("b-2"),
				},
			},
		},
		.profiles = {
			{ .id = ProfileId("safe"), .accountIds = { AccountId("account-b") } },
			{ .id = ProfileId("unsafe"), .accountIds = { AccountId("account-a") } },
			{ .id = ProfileId("empty"), .accountIds = {} },
		},
	};
}

bool HasNotice(const DryRunPlan &plan, PlanNotice notice) {
	return std::ranges::find(plan.notices, notice) != plan.notices.end();
}

bool HasIssue(const DryRunPlan &plan, PlanIssue issue) {
	return std::ranges::find(plan.issues, issue) != plan.issues.end();
}

void SelectedScopeUsesStableLiveIds() {
	auto rule = BaseRule();
	rule.selectedAccountIds = {
		AccountId("account-a"),
		AccountId("removed-account"),
	};
	auto plan = BuildDryRunPlan(
		OperationId("operation-a"),
		rule,
		BaseLive());
	Check("selected-scope-targets-live-id-only",
		plan.status == DryRunStatus::Ready
		&& plan.accounts.size() == 1
		&& plan.accounts.front().accountId == AccountId("account-a"));
	Check("removed-account-is-reported-not-replaced",
		HasNotice(plan, PlanNotice::SelectedAccountNotLive)
		&& plan.selectedAccountIdsNotLive
			== std::vector<AccountId>{ AccountId("removed-account") });
}

void RemoteTargetsResolveAgainstCurrentSessions() {
	auto rule = BaseRule();
	rule.targetScope = TargetScope::AllAccounts;
	rule.selectedAccountIds.clear();
	rule.remoteSessionPolicies = {
		{ .accountId = AccountId("account-a") },
		{
			.accountId = AccountId("account-b"),
			.kind = RemoteSessionTargetKind::AllOtherSessions,
		},
	};
	auto live = BaseLive();
	live.accounts.push_back({
		.id = AccountId("account-added-later"),
		.currentSessionId = SessionId("new-current"),
		.sessionIds = { SessionId("new-current"), SessionId("new-other") },
	});
	rule.safeProfileId = ProfileId("empty");
	auto plan = BuildDryRunPlan(OperationId("operation-b"), rule, live);
	Check("all-scope-includes-live-added-account",
		plan.accounts.size() == 3
		&& std::ranges::find(plan.accounts, AccountId("account-added-later"),
			&AccountDryRun::accountId) != plan.accounts.end());
	const auto accountB = std::ranges::find(
		plan.accounts, AccountId("account-b"), &AccountDryRun::accountId);
	const auto added = std::ranges::find(
		plan.accounts, AccountId("account-added-later"), &AccountDryRun::accountId);
	Check("all-other-excludes-current-session",
		accountB != plan.accounts.end()
		&& accountB->remoteTarget == RemoteSessionTargetKind::AllOtherSessions
		&& accountB->sessionIdsForRevokeRequest.size() == 2
		&& std::ranges::find(
			accountB->sessionIdsForRevokeRequest,
			SessionId("b-current"))
			== accountB->sessionIdsForRevokeRequest.end());
	Check("new-account-remote-target-defaults-to-none",
		added != plan.accounts.end()
		&& !added->remoteTargetWasConfigured
		&& added->remoteTarget == RemoteSessionTargetKind::None
		&& HasNotice(plan, PlanNotice::RemotePolicyDefaultsToNone));
}

void SelectedRemoteSessionsDoNotSubstitute() {
	auto rule = BaseRule();
	rule.remoteSessionPolicies = {
		{
			.accountId = AccountId("account-a"),
			.kind = RemoteSessionTargetKind::SelectedSessions,
			.selectedSessionIds = {
				SessionId("a-other"),
				SessionId("stale-session"),
			},
		},
	};
	auto plan = BuildDryRunPlan(
		OperationId("operation-c"),
		rule,
		BaseLive());
	Check("selected-session-ids-are-exact",
		plan.accounts.front().sessionIdsForRevokeRequest
			== std::vector<SessionId>{ SessionId("a-other") }
		&& plan.accounts.front().selectedSessionIdsNotLive
			== std::vector<SessionId>{ SessionId("stale-session") });
	Check("current-session-cannot-be-selected-remotely", [&] {
		rule.remoteSessionPolicies.front().selectedSessionIds.push_back(
			SessionId("a-current"));
		const auto current = BuildDryRunPlan(
			OperationId("operation-d"),
			rule,
			BaseLive());
		return current.status == DryRunStatus::Rejected
			&& HasIssue(current, PlanIssue::CurrentSessionCannotBeRemoteTarget);
	}());
}

void SafeProfileMustRemainOutsideTargets() {
	auto rule = BaseRule();
	rule.safeProfileId = ProfileId("unsafe");
	auto plan = BuildDryRunPlan(
		OperationId("operation-e"),
		rule,
		BaseLive());
	Check("selected-safe-profile-overlap-rejected",
		plan.status == DryRunStatus::Rejected
		&& HasIssue(plan, PlanIssue::SafeProfileContainsAffectedAccount));

	rule.targetScope = TargetScope::AllAccounts;
	rule.selectedAccountIds.clear();
	rule.safeProfileId = ProfileId("empty");
	plan = BuildDryRunPlan(OperationId("operation-f"), rule, BaseLive());
	Check("reset-all-allows-empty-safe-profile",
		plan.status == DryRunStatus::Ready
		&& plan.safeDestination == SafeDestinationKind::Profile);
	rule.safeProfileId = ProfileId("safe");
	plan = BuildDryRunPlan(OperationId("operation-f2"), rule, BaseLive());
	Check("reset-all-rejects-nonempty-safe-profile",
		plan.status == DryRunStatus::Rejected
		&& HasIssue(plan, PlanIssue::SafeProfileContainsAffectedAccount));
}

void InstallationTargetIsExplicitAndDryRunOnly() {
	auto rule = BaseRule();
	rule.action = EmergencyAction::RemoveInstallation;
	rule.targetScope = TargetScope::CurrentInstallation;
	rule.selectedAccountIds.clear();
	rule.safeProfileId = ProfileId("empty");
	auto plan = BuildDryRunPlan(
		OperationId("operation-g"),
		rule,
		BaseLive());
	Check("installation-target-is-explicit",
		plan.status == DryRunStatus::Ready
		&& plan.wouldRemoveInstallation
		&& plan.accounts.size() == 2
		&& plan.safeDestination == SafeDestinationKind::None);
	const auto repeated = BuildDryRunPlan(
		OperationId("operation-g"),
		rule,
		BaseLive());
	Check("same-operation-and-live-snapshot-produce-same-plan",
		repeated.operationId == plan.operationId
		&& repeated.accounts.size() == plan.accounts.size()
		&& repeated.accounts[0].accountId == plan.accounts[0].accountId
		&& repeated.accounts[0].remoteTarget == plan.accounts[0].remoteTarget
		&& repeated.wouldRemoveInstallation == plan.wouldRemoveInstallation);
}

void InvalidScopeCombinationIsRejected() {
	auto rule = BaseRule();
	rule.action = EmergencyAction::RemoveInstallation;
	rule.targetScope = TargetScope::AllAccounts;
	rule.selectedAccountIds.clear();
	const auto plan = BuildDryRunPlan(
		OperationId("operation-h"),
		rule,
		BaseLive());
	Check("remove-installation-requires-current-installation-scope",
		plan.status == DryRunStatus::Rejected
		&& HasIssue(plan, PlanIssue::InvalidTargetAction));
}

} // namespace

int main() {
	SelectedScopeUsesStableLiveIds();
	RemoteTargetsResolveAgainstCurrentSessions();
	SelectedRemoteSessionsDoNotSubstitute();
	SafeProfileMustRemainOutsideTargets();
	InstallationTargetIsExplicitAndDryRunOnly();
	InvalidScopeCombinationIsRejected();
	return failures ? 1 : 0;
}
