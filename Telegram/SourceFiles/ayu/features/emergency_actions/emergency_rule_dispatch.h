// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_plan.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

namespace Ayu::EmergencyActions {

inline constexpr auto kCredentialVerifierBytes = size_t(32);
// This is a fixed-size KDF output; passcode text never enters this model.
using CredentialVerifier = std::array<uint8_t, kCredentialVerifierBytes>;

struct NormalCredential final {
	NormalPasscodeId id;
	CredentialVerifier verifier;
};

struct ConfirmedDraft final {
	uint64_t revision = 0;
	EmergencyRule reviewedRule;
	CredentialVerifier reviewedVerifier;
	DryRunPlan reviewedPlan;
};

struct EmergencyRuleDraft final {
	EmergencyActionId id;
	EmergencyRule rule;
	CredentialVerifier verifier;
	uint64_t revision = 1;
	std::optional<ConfirmedDraft> confirmed;
};

struct RuleConfiguration final {
	InstallationId activeInstallationId;
	CredentialVerifier masterVerifier;
	std::vector<NormalCredential> normalCredentials;
	std::vector<EmergencyRuleDraft> emergencyRules;
};

enum class RuleValidationError : uint8_t {
	None,
	InvalidInstallationId,
	DuplicateNormalPasscodeId,
	InvalidEmergencyActionId,
	DuplicateEmergencyActionId,
	InvalidRuleId,
	DuplicateRuleId,
	RuleInstallationMismatch,
	InvalidRevision,
	InvalidCredentialVerifier,
	InvalidConfirmation,
	DuplicateCredentialVerifier,
	TooManyRules,
};

struct DraftPreview final {
	EmergencyActionId id;
	uint64_t revision = 0;
	InstallationId installationId;
	DryRunPlan plan;
};

struct WrongPasscode final {
	friend inline auto operator<=>(WrongPasscode, WrongPasscode) = default;
};

struct MasterPasscodeMatch final {
	friend inline auto operator<=>(MasterPasscodeMatch, MasterPasscodeMatch) = default;
};

struct NormalPasscodeMatch final {
	NormalPasscodeId id;
};

struct EmergencyActionMatch final {
	EmergencyActionId id;
};

using PasswordCheckRoute = std::variant<
	WrongPasscode,
	MasterPasscodeMatch,
	NormalPasscodeMatch>;
using LockScreenRoute = std::variant<
	WrongPasscode,
	MasterPasscodeMatch,
	NormalPasscodeMatch,
	EmergencyActionMatch>;

enum class NonLockScreenPurpose : uint8_t {
	SettingsPasswordCheck,
	WalletUnlock,
	SettingsConfirmation,
};

[[nodiscard]] RuleValidationError ValidateRuleConfiguration(
	const RuleConfiguration &configuration);

[[nodiscard]] std::optional<DraftPreview> PreviewEmergencyRule(
	const RuleConfiguration &configuration,
	const EmergencyActionId &id,
	const LiveInstallation &currentSnapshot,
	OperationId previewOperationId);

[[nodiscard]] bool ConfirmEmergencyRule(
	RuleConfiguration &configuration,
	const DraftPreview &preview,
	const LiveInstallation &currentSnapshot,
	bool explicitlyConfirmedOutcomes);

[[nodiscard]] bool ReviseEmergencyRule(
	RuleConfiguration &configuration,
	const EmergencyActionId &id,
	EmergencyRule revisedRule,
	CredentialVerifier revisedVerifier);

[[nodiscard]] PasswordCheckRoute CheckNonLockScreenPasscode(
	NonLockScreenPurpose purpose,
	const RuleConfiguration &configuration,
	const CredentialVerifier &verifier);

struct LockScreenSubmit final {
	friend inline auto operator<=>(LockScreenSubmit, LockScreenSubmit) = default;
};

[[nodiscard]] LockScreenRoute DispatchLockScreenPasscode(
	LockScreenSubmit,
	const RuleConfiguration &configuration,
	const CredentialVerifier &verifier);

} // namespace Ayu::EmergencyActions
