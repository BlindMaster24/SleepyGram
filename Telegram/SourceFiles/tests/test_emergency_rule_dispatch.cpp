#include "ayu/features/emergency_actions/emergency_rule_dispatch.h"

#include <algorithm>
#include <cstdio>
#include <type_traits>
#include <variant>
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
		.id = RuleId("rule-1"),
		.installationId = InstallationId("install-1"),
		.action = EmergencyAction::ResetAccountData,
		.targetScope = TargetScope::SelectedAccounts,
		.selectedAccountIds = { AccountId("account-a") },
		.remoteSessionPolicies = {
			{
				.accountId = AccountId("account-a"),
				.kind = RemoteSessionTargetKind::AllOtherSessions,
			},
		},
		.safeProfileId = ProfileId("empty-safe"),
	};
}

LiveInstallation Live() {
	return {
		.id = InstallationId("install-1"),
		.accounts = {
			{
				.id = AccountId("account-a"),
				.currentSessionId = SessionId("current-a"),
				.sessionIds = { SessionId("current-a"), SessionId("other-a") },
			},
		},
		.profiles = {
			{ .id = ProfileId("empty-safe"), .accountIds = {} },
		},
	};
}

RuleConfiguration Configuration() {
	return {
		.activeInstallationId = InstallationId("install-1"),
		.masterVerifier = Verifier(0xE0),
		.normalCredentials = {
			{ .id = NormalPasscodeId("set-one"), .verifier = Verifier(0x10) },
		},
		.emergencyRules = {
			{
				.id = EmergencyActionId("action-one"),
				.rule = Rule(),
				.verifier = Verifier(0x20),
				.revision = 1,
			},
		},
	};
}

bool IsEmergency(const LockScreenRoute &route, const EmergencyActionId &id) {
	const auto action = std::get_if<EmergencyActionMatch>(&route);
	return action && action->id == id;
}

void ValidateUniqueCredentialVerifiersAndInstallationBinding() {
	auto config = Configuration();
	Check("valid-rule-configuration", ValidateRuleConfiguration(config)
		== RuleValidationError::None);
	config.emergencyRules.front().rule.installationId
		= InstallationId("other-install");
	Check("rules-bind-to-active-installation", ValidateRuleConfiguration(config)
		== RuleValidationError::RuleInstallationMismatch);
	config = Configuration();
	config.emergencyRules.front().verifier = Verifier(0x10);
	Check("emergency-verifier-cannot-collide-with-normal-passcode",
		ValidateRuleConfiguration(config)
			== RuleValidationError::DuplicateCredentialVerifier);
	config = Configuration();
	config.masterVerifier = config.emergencyRules.front().verifier;
	Check("emergency-verifier-cannot-collide-with-master",
		ValidateRuleConfiguration(config)
			== RuleValidationError::DuplicateCredentialVerifier);
	config = Configuration();
	config.emergencyRules.push_back(config.emergencyRules.front());
	config.emergencyRules.back().id = EmergencyActionId("action-two");
	config.emergencyRules.back().rule.id = RuleId("rule-two");
	Check("emergency-verifiers-are-mutually-unique",
		ValidateRuleConfiguration(config)
			== RuleValidationError::DuplicateCredentialVerifier);
}

void DraftRequiresCurrentExactPreviewAndExplicitConfirmation() {
	auto config = Configuration();
	const auto actionId = EmergencyActionId("action-one");
	auto live = Live();
	const auto preview = PreviewEmergencyRule(
		config,
		actionId,
		live,
		OperationId("preview-1"));
	Check("valid-draft-produces-live-preview",
		preview && preview->plan.status == DryRunStatus::Ready);
	Check("draft-is-inactive-before-confirmation",
		!config.emergencyRules.front().confirmed
		&& !IsEmergency(DispatchLockScreenPasscode(
			LockScreenSubmit(), config, Verifier(0x20)), actionId));
	Check("outcome-confirmation-is-required",
		preview
		&& !ConfirmEmergencyRule(config, *preview, live, false)
		&& !config.emergencyRules.front().confirmed);
	if (!preview) return;
	Check("live-snapshot-must-match-reviewed-outcomes", [&] {
		auto changed = live;
		changed.accounts.front().sessionIds.push_back(SessionId("other-added"));
		return !ConfirmEmergencyRule(config, *preview, changed, true)
			&& !config.emergencyRules.front().confirmed;
	}());
	Check("exact-review-activates-current-revision",
		ConfirmEmergencyRule(config, *preview, live, true)
		&& config.emergencyRules.front().confirmed->revision == 1
		&& config.emergencyRules.front().confirmed->reviewedPlan == preview->plan);
	Check("explicit-lock-screen-submit-dispatches-action-id",
		IsEmergency(DispatchLockScreenPasscode(
			LockScreenSubmit(), config, Verifier(0x20)), actionId));
}

void OtherPasswordChecksCannotYieldEmergencyActionType() {
	static_assert(!std::is_same_v<PasswordCheckRoute, LockScreenRoute>);
	static_assert(!std::is_constructible_v<PasswordCheckRoute, EmergencyActionMatch>);
	auto config = Configuration();
	auto live = Live();
	const auto preview = PreviewEmergencyRule(
		config,
		EmergencyActionId("action-one"),
		live,
		OperationId("preview-2"));
	if (!preview || !ConfirmEmergencyRule(config, *preview, live, true)) {
		Check("configured-rule-can-be-confirmed", false);
		return;
	}
	for (const auto purpose : {
			NonLockScreenPurpose::SettingsPasswordCheck,
			NonLockScreenPurpose::WalletUnlock,
			NonLockScreenPurpose::SettingsConfirmation }) {
		const auto result = CheckNonLockScreenPasscode(
			purpose,
			config,
			Verifier(0x20));
		Check("non-lock-screen-check-rejects-emergency-passcode",
			std::holds_alternative<WrongPasscode>(result));
	}
	const auto normalRoute = CheckNonLockScreenPasscode(
		NonLockScreenPurpose::WalletUnlock,
		config,
		Verifier(0x10));
	Check("normal-passcode-still-routes-through-password-check",
		std::get_if<NormalPasscodeMatch>(&normalRoute) != nullptr);
	Check("master-passcode-still-routes-through-password-check",
		std::holds_alternative<MasterPasscodeMatch>(CheckNonLockScreenPasscode(
			NonLockScreenPurpose::SettingsConfirmation,
			config,
			Verifier(0xE0))));
}

void NewRevisionInvalidatesOldConfirmationAndPreview() {
	auto config = Configuration();
	const auto id = EmergencyActionId("action-one");
	auto live = Live();
	const auto oldPreview = PreviewEmergencyRule(
		config,
		id,
		live,
		OperationId("preview-old"));
	if (!oldPreview || !ConfirmEmergencyRule(config, *oldPreview, live, true)) {
		Check("first-revision-can-be-confirmed", false);
		return;
	}
	Check("first-revision-is-active", IsEmergency(
		DispatchLockScreenPasscode(LockScreenSubmit(), config, Verifier(0x20)),
		id));
	Check("editing-revision-revokes-previous-activation",
		ReviseEmergencyRule(
			config,
			id,
			Rule(),
			Verifier(0x30))
		&& config.emergencyRules.front().revision == 2
		&& !config.emergencyRules.front().confirmed
		&& !IsEmergency(DispatchLockScreenPasscode(
			LockScreenSubmit(), config, Verifier(0x20)), id));
	Check("stale-preview-cannot-confirm-new-revision",
		!ConfirmEmergencyRule(config, *oldPreview, live, true));
	const auto newPreview = PreviewEmergencyRule(
		config,
		id,
		live,
		OperationId("preview-new"));
	Check("latest-revision-replaces-old-credential-after-confirmation",
		newPreview
		&& ConfirmEmergencyRule(config, *newPreview, live, true)
		&& !IsEmergency(DispatchLockScreenPasscode(
			LockScreenSubmit(), config, Verifier(0x20)), id)
		&& IsEmergency(DispatchLockScreenPasscode(
			LockScreenSubmit(), config, Verifier(0x30)), id));
}

void InvalidOrUnconfirmedDraftNeverDispatches() {
	auto config = Configuration();
	config.emergencyRules.front().rule.installationId
		= InstallationId("wrong-install");
	Check("installation-mismatch-disables-emergency-route",
		ValidateRuleConfiguration(config)
			== RuleValidationError::RuleInstallationMismatch
		&& !IsEmergency(DispatchLockScreenPasscode(
			LockScreenSubmit(), config, Verifier(0x20)),
			EmergencyActionId("action-one")));
	config = Configuration();
	auto live = Live();
	Check("unsafe-preview-is-not-confirmable",
		!PreviewEmergencyRule(
			config,
			EmergencyActionId("action-one"),
			LiveInstallation{ .id = InstallationId("other-install") },
			OperationId("preview-wrong-install")));
	config = Configuration();
	const auto preview = PreviewEmergencyRule(
		config,
		EmergencyActionId("action-one"),
		Live(),
		OperationId("preview-tamper"));
	if (preview && ConfirmEmergencyRule(config, *preview, Live(), true)) {
		config.emergencyRules.front().verifier = Verifier(0x30);
		Check("edited-verifier-invalidates-confirmed-revision",
			ValidateRuleConfiguration(config)
				== RuleValidationError::InvalidConfirmation
			&& !IsEmergency(DispatchLockScreenPasscode(
				LockScreenSubmit(), config, Verifier(0x30)),
				EmergencyActionId("action-one")));
	} else {
		Check("edited-verifier-invalidates-confirmed-revision", false);
	}
}

} // namespace

int main() {
	ValidateUniqueCredentialVerifiersAndInstallationBinding();
	DraftRequiresCurrentExactPreviewAndExplicitConfirmation();
	OtherPasswordChecksCannotYieldEmergencyActionType();
	NewRevisionInvalidatesOldConfirmationAndPreview();
	InvalidOrUnconfirmedDraftNeverDispatches();
	return failures ? 1 : 0;
}
