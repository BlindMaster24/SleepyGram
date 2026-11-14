// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/emergency_rule_dispatch.h"

#include <algorithm>
#include <limits>
#include <ranges>
#include <set>

namespace Ayu::EmergencyActions {
namespace {

bool SameVerifier(
		const CredentialVerifier &a,
		const CredentialVerifier &b) {
	auto difference = uint8_t(0);
	for (auto i = size_t(0); i != a.size(); ++i) {
		difference |= a[i] ^ b[i];
	}
	return difference == 0;
}

bool HasVerifier(const CredentialVerifier &verifier) {
	auto value = uint8_t(0);
	for (const auto byte : verifier) {
		value |= byte;
	}
	return value != 0;
}

bool ValidBaseCredentials(const RuleConfiguration &configuration) {
	if (!configuration.activeInstallationId.valid()
		|| !HasVerifier(configuration.masterVerifier)) {
		return false;
	}
	auto ids = std::set<NormalPasscodeId>();
	auto verifiers = std::vector<CredentialVerifier>{
		configuration.masterVerifier };
	for (const auto &normal : configuration.normalCredentials) {
		if (!normal.id.valid() || !HasVerifier(normal.verifier)
			|| !ids.insert(normal.id).second) {
			return false;
		}
		verifiers.push_back(normal.verifier);
	}
	for (auto i = size_t(0); i != verifiers.size(); ++i) {
		for (auto j = i + 1; j != verifiers.size(); ++j) {
			if (SameVerifier(verifiers[i], verifiers[j])) {
				return false;
			}
		}
	}
	return true;
}

PasswordCheckRoute MatchBaseCredentials(
		const RuleConfiguration &configuration,
		const CredentialVerifier &verifier) {
	if (!ValidBaseCredentials(configuration)) {
		return WrongPasscode();
	}
	if (SameVerifier(configuration.masterVerifier, verifier)) {
		return MasterPasscodeMatch();
	}
	for (const auto &normal : configuration.normalCredentials) {
		if (SameVerifier(normal.verifier, verifier)) {
			return NormalPasscodeMatch{ normal.id };
		}
	}
	return WrongPasscode();
}

auto FindDraft(RuleConfiguration &configuration, const EmergencyActionId &id) {
	return std::ranges::find(configuration.emergencyRules, id, &EmergencyRuleDraft::id);
}

auto FindDraft(
		const RuleConfiguration &configuration,
		const EmergencyActionId &id) {
	return std::ranges::find(configuration.emergencyRules, id, &EmergencyRuleDraft::id);
}

} // namespace

RuleValidationError ValidateRuleConfiguration(
		const RuleConfiguration &configuration) {
	if (!configuration.activeInstallationId.valid()) {
		return RuleValidationError::InvalidInstallationId;
	}
	if (!HasVerifier(configuration.masterVerifier)
		|| std::ranges::any_of(configuration.normalCredentials, [](const auto &value) {
			return !HasVerifier(value.verifier);
		})
		|| std::ranges::any_of(configuration.emergencyRules, [](const auto &value) {
			return !HasVerifier(value.verifier);
		})) {
		return RuleValidationError::InvalidCredentialVerifier;
	}
	if (!ValidBaseCredentials(configuration)) {
		return RuleValidationError::DuplicateNormalPasscodeId;
	}
	if (configuration.emergencyRules.size() > 256) {
		return RuleValidationError::TooManyRules;
	}
	auto actionIds = std::set<EmergencyActionId>();
	auto ruleIds = std::set<RuleId>();
	auto verifiers = std::vector<CredentialVerifier>{
		configuration.masterVerifier };
	for (const auto &normal : configuration.normalCredentials) {
		verifiers.push_back(normal.verifier);
	}
	for (const auto &draft : configuration.emergencyRules) {
		if (!draft.id.valid()) {
			return RuleValidationError::InvalidEmergencyActionId;
		}
		if (!actionIds.insert(draft.id).second) {
			return RuleValidationError::DuplicateEmergencyActionId;
		}
		if (!draft.rule.id.valid()) {
			return RuleValidationError::InvalidRuleId;
		}
		if (!ruleIds.insert(draft.rule.id).second) {
			return RuleValidationError::DuplicateRuleId;
		}
		if (draft.rule.installationId != configuration.activeInstallationId) {
			return RuleValidationError::RuleInstallationMismatch;
		}
		if (!draft.revision
			|| (draft.confirmed && draft.confirmed->revision != draft.revision)) {
			return RuleValidationError::InvalidRevision;
		}
		if (draft.confirmed
			&& (draft.confirmed->reviewedRule != draft.rule
				|| !SameVerifier(draft.confirmed->reviewedVerifier, draft.verifier)
				|| draft.confirmed->reviewedPlan.status != DryRunStatus::Ready
				|| draft.confirmed->reviewedPlan.ruleId != draft.rule.id
				|| draft.confirmed->reviewedPlan.installationId
					!= configuration.activeInstallationId
				|| draft.confirmed->reviewedPlan.action != draft.rule.action
				|| draft.confirmed->reviewedPlan.targetScope != draft.rule.targetScope)) {
			return RuleValidationError::InvalidConfirmation;
		}
		verifiers.push_back(draft.verifier);
	}
	for (auto i = size_t(0); i != verifiers.size(); ++i) {
		for (auto j = i + 1; j != verifiers.size(); ++j) {
			if (SameVerifier(verifiers[i], verifiers[j])) {
				return RuleValidationError::DuplicateCredentialVerifier;
			}
		}
	}
	return RuleValidationError::None;
}

std::optional<DraftPreview> PreviewEmergencyRule(
		const RuleConfiguration &configuration,
		const EmergencyActionId &id,
		const LiveInstallation &currentSnapshot,
		OperationId previewOperationId) {
	if (ValidateRuleConfiguration(configuration) != RuleValidationError::None
		|| currentSnapshot.id != configuration.activeInstallationId) {
		return std::nullopt;
	}
	const auto draft = FindDraft(configuration, id);
	if (draft == configuration.emergencyRules.end()) {
		return std::nullopt;
	}
	auto plan = BuildDryRunPlan(
		std::move(previewOperationId),
		draft->rule,
		currentSnapshot);
	if (plan.status != DryRunStatus::Ready) {
		return std::nullopt;
	}
	return DraftPreview{
		.id = draft->id,
		.revision = draft->revision,
		.installationId = currentSnapshot.id,
		.plan = std::move(plan),
	};
}

bool ConfirmEmergencyRule(
		RuleConfiguration &configuration,
		const DraftPreview &preview,
		const LiveInstallation &currentSnapshot,
		bool explicitlyConfirmedOutcomes) {
	if (!explicitlyConfirmedOutcomes
		|| ValidateRuleConfiguration(configuration) != RuleValidationError::None
		|| preview.installationId != configuration.activeInstallationId
		|| currentSnapshot.id != configuration.activeInstallationId) {
		return false;
	}
	const auto draft = FindDraft(configuration, preview.id);
	if (draft == configuration.emergencyRules.end()
		|| draft->revision != preview.revision
		|| preview.plan.installationId != configuration.activeInstallationId) {
		return false;
	}
	const auto currentPlan = BuildDryRunPlan(
		preview.plan.operationId,
		draft->rule,
		currentSnapshot);
	if (currentPlan.status != DryRunStatus::Ready
		|| currentPlan != preview.plan) {
		return false;
	}
	draft->confirmed = ConfirmedDraft{
		.revision = draft->revision,
		.reviewedRule = draft->rule,
		.reviewedVerifier = draft->verifier,
		.reviewedPlan = currentPlan,
	};
	return true;
}

bool ReviseEmergencyRule(
		RuleConfiguration &configuration,
		const EmergencyActionId &id,
		EmergencyRule revisedRule,
		CredentialVerifier revisedVerifier) {
	const auto draft = FindDraft(configuration, id);
	if (draft == configuration.emergencyRules.end()
		|| draft->revision == std::numeric_limits<uint64_t>::max()) {
		return false;
	}
	draft->rule = std::move(revisedRule);
	draft->verifier = revisedVerifier;
	++draft->revision;
	draft->confirmed.reset();
	return true;
}

PasswordCheckRoute CheckNonLockScreenPasscode(
		NonLockScreenPurpose purpose,
		const RuleConfiguration &configuration,
		const CredentialVerifier &verifier) {
	if (uint8_t(purpose) > uint8_t(NonLockScreenPurpose::SettingsConfirmation)) {
		return WrongPasscode();
	}
	return MatchBaseCredentials(configuration, verifier);
}

LockScreenRoute DispatchLockScreenPasscode(
		LockScreenSubmit,
		const RuleConfiguration &configuration,
		const CredentialVerifier &verifier) {
	const auto base = MatchBaseCredentials(configuration, verifier);
	if (const auto wrong = std::get_if<WrongPasscode>(&base)) {
		if (ValidateRuleConfiguration(configuration) != RuleValidationError::None) {
			return *wrong;
		}
		for (const auto &draft : configuration.emergencyRules) {
			if (draft.confirmed
				&& draft.confirmed->revision == draft.revision
				&& draft.confirmed->reviewedPlan.installationId
					== configuration.activeInstallationId
				&& SameVerifier(draft.verifier, verifier)) {
				return EmergencyActionMatch{ draft.id };
			}
		}
		return *wrong;
	}
	if (const auto master = std::get_if<MasterPasscodeMatch>(&base)) {
		return *master;
	}
	return std::get<NormalPasscodeMatch>(base);
}

} // namespace Ayu::EmergencyActions
