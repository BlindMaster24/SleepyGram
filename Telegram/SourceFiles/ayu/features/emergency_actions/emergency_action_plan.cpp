// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_action_plan.h"

#include <algorithm>
#include <set>

namespace Ayu::EmergencyActions {
namespace {

template <typename Value>
bool HasDuplicates(const std::vector<Value> &values) {
	auto sorted = values;
	std::ranges::sort(sorted);
	return std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end();
}

void AddIssue(DryRunPlan &plan, PlanIssue issue) {
	if (std::ranges::find(plan.issues, issue) == plan.issues.end()) {
		plan.issues.push_back(issue);
	}
	plan.status = DryRunStatus::Rejected;
}

void AddNotice(DryRunPlan &plan, PlanNotice notice) {
	if (std::ranges::find(plan.notices, notice) == plan.notices.end()) {
		plan.notices.push_back(notice);
	}
}

const RemoteSessionPolicy *PolicyFor(
		const EmergencyRule &rule,
		AccountId accountId) {
	const auto i = std::ranges::find(
		rule.remoteSessionPolicies,
		accountId,
		&RemoteSessionPolicy::accountId);
	return (i == rule.remoteSessionPolicies.end()) ? nullptr : &*i;
}

const LiveAccount *LiveAccountFor(
		const LiveInstallation &live,
		AccountId accountId) {
	const auto i = std::ranges::find(
		live.accounts,
		accountId,
		&LiveAccount::id);
	return (i == live.accounts.end()) ? nullptr : &*i;
}

const LiveProfile *LiveProfileFor(
		const LiveInstallation &live,
		ProfileId profileId) {
	const auto i = std::ranges::find(
		live.profiles,
		profileId,
		&LiveProfile::id);
	return (i == live.profiles.end()) ? nullptr : &*i;
}

bool HasDuplicatePolicies(const std::vector<RemoteSessionPolicy> &policies) {
	auto ids = std::vector<AccountId>();
	ids.reserve(policies.size());
	for (const auto &policy : policies) ids.push_back(policy.accountId);
	return HasDuplicates(ids);
}

bool ValidRemotePolicy(const RemoteSessionPolicy &policy) {
	if (!policy.accountId.valid() || HasDuplicates(policy.selectedSessionIds)) {
		return false;
	}
	switch (policy.kind) {
	case RemoteSessionTargetKind::None:
	case RemoteSessionTargetKind::AllOtherSessions:
		return policy.selectedSessionIds.empty();
	case RemoteSessionTargetKind::SelectedSessions:
		return !policy.selectedSessionIds.empty()
			&& std::ranges::all_of(policy.selectedSessionIds, &SessionId::valid);
	}
	return false;
}

bool ValidLiveAccount(const LiveAccount &account) {
	return account.id.valid()
		&& account.currentSessionId.valid()
		&& !account.sessionIds.empty()
		&& !HasDuplicates(account.sessionIds)
		&& std::ranges::all_of(account.sessionIds, &SessionId::valid)
		&& std::ranges::find(account.sessionIds, account.currentSessionId) != account.sessionIds.end();
}

std::vector<AccountId> TargetAccountIds(
		DryRunPlan &plan,
		const EmergencyRule &rule,
		const LiveInstallation &live) {
	auto result = std::vector<AccountId>();
	switch (rule.targetScope) {
	case TargetScope::SelectedAccounts: {
		if (rule.selectedAccountIds.empty()) {
			AddIssue(plan, PlanIssue::EmptySelectedAccounts);
			return result;
		}
		for (const auto &id : rule.selectedAccountIds) {
			if (!id.valid()) {
				AddIssue(plan, PlanIssue::InvalidConfiguredId);
				continue;
			}
			if (!LiveAccountFor(live, id)) {
				AddNotice(plan, PlanNotice::SelectedAccountNotLive);
				plan.selectedAccountIdsNotLive.push_back(id);
				continue;
			}
			result.push_back(id);
		}
		if (HasDuplicates(rule.selectedAccountIds)) {
			AddIssue(plan, PlanIssue::DuplicateConfiguredId);
		}
		break;
	}
	case TargetScope::AllAccounts:
	case TargetScope::CurrentInstallation:
		if (!rule.selectedAccountIds.empty()) {
			AddIssue(plan, PlanIssue::InvalidTargetAction);
		}
		for (const auto &account : live.accounts) {
			result.push_back(account.id);
		}
		break;
	}
	std::ranges::sort(result);
	return result;
}

} // namespace

DryRunPlan BuildDryRunPlan(
		OperationId operationId,
		const EmergencyRule &rule,
		const LiveInstallation &live) {
	auto result = DryRunPlan{
		.operationId = std::move(operationId),
		.ruleId = rule.id,
		.installationId = rule.installationId,
		.action = rule.action,
		.targetScope = rule.targetScope,
		.wouldRemoveInstallation = (rule.action == EmergencyAction::RemoveInstallation),
	};
	if (!result.operationId.valid()) {
		AddIssue(result, PlanIssue::InvalidOperationId);
	}
	if (!rule.id.valid()) {
		AddIssue(result, PlanIssue::InvalidRuleId);
	}
	if (!rule.installationId.valid() || !live.id.valid()
		|| rule.installationId != live.id) {
		AddIssue(result, PlanIssue::InvalidInstallationId);
	}
	if ((rule.action == EmergencyAction::RemoveInstallation
			&& rule.targetScope != TargetScope::CurrentInstallation)
		|| (rule.action == EmergencyAction::ResetAccountData
			&& rule.targetScope == TargetScope::CurrentInstallation)) {
		AddIssue(result, PlanIssue::InvalidTargetAction);
	}
	if (HasDuplicatePolicies(rule.remoteSessionPolicies)) {
		AddIssue(result, PlanIssue::DuplicateConfiguredId);
	}
	for (const auto &policy : rule.remoteSessionPolicies) {
		if (!ValidRemotePolicy(policy)) {
			AddIssue(result, PlanIssue::InvalidRemoteSessionPolicy);
		}
	}
	if (!std::ranges::all_of(live.accounts, ValidLiveAccount)
		|| HasDuplicates([&] {
			auto ids = std::vector<AccountId>();
			for (const auto &account : live.accounts) ids.push_back(account.id);
			return ids;
		}())
		|| HasDuplicates([&] {
			auto ids = std::vector<ProfileId>();
			for (const auto &profile : live.profiles) ids.push_back(profile.id);
			return ids;
		}())) {
		AddIssue(result, PlanIssue::InvalidLiveSnapshot);
	}
	for (const auto &profile : live.profiles) {
		if (!profile.id.valid() || HasDuplicates(profile.accountIds)
			|| !std::ranges::all_of(profile.accountIds, &AccountId::valid)) {
			AddIssue(result, PlanIssue::InvalidLiveSnapshot);
		}
	}
	auto targetIds = TargetAccountIds(result, rule, live);
	for (const auto &id : targetIds) {
		const auto account = LiveAccountFor(live, id);
		if (!account) {
			continue;
		}
		auto effect = AccountDryRun{ .accountId = id };
		const auto policy = PolicyFor(rule, id);
		if (!policy) {
			AddNotice(result, PlanNotice::RemotePolicyDefaultsToNone);
		} else {
			effect.remoteTargetWasConfigured = true;
			effect.remoteTarget = policy->kind;
			if (policy->kind == RemoteSessionTargetKind::SelectedSessions) {
				for (const auto &sessionId : policy->selectedSessionIds) {
					if (sessionId == account->currentSessionId) {
						AddIssue(result, PlanIssue::CurrentSessionCannotBeRemoteTarget);
					} else if (std::ranges::find(account->sessionIds, sessionId) != account->sessionIds.end()) {
						effect.sessionIdsForRevokeRequest.push_back(sessionId);
					} else {
						effect.selectedSessionIdsNotLive.push_back(sessionId);
						AddNotice(result, PlanNotice::SelectedRemoteSessionNotLive);
					}
				}
			} else if (policy->kind == RemoteSessionTargetKind::AllOtherSessions) {
				for (const auto &sessionId : account->sessionIds) {
					if (sessionId != account->currentSessionId) {
						effect.sessionIdsForRevokeRequest.push_back(sessionId);
					}
				}
			}
		}
		std::ranges::sort(effect.sessionIdsForRevokeRequest);
		std::ranges::sort(effect.selectedSessionIdsNotLive);
		result.accounts.push_back(std::move(effect));
	}
	if (rule.action == EmergencyAction::ResetAccountData) {
		if (rule.safeProfileId.valid()) {
			if (const auto profile = LiveProfileFor(live, rule.safeProfileId)) {
				result.safeDestination = SafeDestinationKind::Profile;
				result.safeProfileId = profile->id;
				result.safeProfileAccountIds = profile->accountIds;
				std::ranges::sort(result.safeProfileAccountIds);
				for (const auto &id : targetIds) {
					if (std::ranges::find(profile->accountIds, id) != profile->accountIds.end()) {
						AddIssue(result, PlanIssue::SafeProfileContainsAffectedAccount);
					}
				}
				if (rule.targetScope == TargetScope::AllAccounts
					&& !profile->accountIds.empty()) {
					AddIssue(result, PlanIssue::SafeProfileContainsAffectedAccount);
				}
			} else {
				result.safeDestination = SafeDestinationKind::AddAccount;
				AddNotice(result, PlanNotice::SafeProfileUnavailable);
			}
		} else {
			result.safeDestination = SafeDestinationKind::AddAccount;
			AddNotice(result, PlanNotice::SafeProfileUnavailable);
		}
	}
	if (rule.action == EmergencyAction::RemoveInstallation) {
		result.safeDestination = SafeDestinationKind::None;
		if (rule.safeProfileId.valid()) {
			if (const auto profile = LiveProfileFor(live, rule.safeProfileId)) {
				result.safeProfileId = profile->id;
				result.safeProfileAccountIds = profile->accountIds;
				std::ranges::sort(result.safeProfileAccountIds);
				if (!profile->accountIds.empty()) {
					AddIssue(result, PlanIssue::SafeProfileContainsAffectedAccount);
				}
			} else {
				AddNotice(result, PlanNotice::SafeProfileUnavailable);
			}
		}
	}
	return result;
}

} // namespace Ayu::EmergencyActions
