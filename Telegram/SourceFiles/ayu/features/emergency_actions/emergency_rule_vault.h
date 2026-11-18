// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/lock_screen_submission.h"

#include <span>

namespace Ayu::EmergencyActions {

inline constexpr auto kMaxSealedEmergencyRules = size_t(16);

struct EmergencyRuleGeneration final {
	InstallationId installationId;
	std::string transactionId;

	friend bool operator==(
		const EmergencyRuleGeneration&,
		const EmergencyRuleGeneration&) = default;
};

struct EmergencyRuleAuthority final {
	EmergencyRuleGeneration generation;
	std::array<uint8_t, 32> digest{};

	friend bool operator==(
		const EmergencyRuleAuthority&,
		const EmergencyRuleAuthority&) = default;
};

struct SealedEmergencyRules final {
	std::vector<uint8_t> bytes;
	EmergencyRuleAuthority authority;
};

struct EmergencyRuleSealInput final {
	EmergencyActionId actionId;
	std::string name;
	CredentialVerifier verifier;
	std::span<const uint8_t> key;
};

struct EmergencyRuleMasterContext final {
	std::span<const uint8_t> derivedKey;
	CredentialVerifier verifier;
	std::span<const NormalCredential> normalCredentials;
};

struct EmergencyRuleDetails final {
	EmergencyActionId actionId;
	EmergencyRule rule;
	OperationId operationId;
	uint64_t revision = 0;
};

struct NamedEmergencyRule final {
	std::string name;
	EmergencyRuleDetails details;
};

class EmergencyRuleTicket;
using EmergencyRuleAuthentication = std::variant<
	WrongPasscode,
	EmergencyVaultUnavailable,
	EmergencyRuleTicket>;

class EmergencyRuleTicket final {
public:
	EmergencyRuleTicket(EmergencyRuleTicket&&) noexcept = default;
	EmergencyRuleTicket &operator=(EmergencyRuleTicket&&) noexcept = default;

	[[nodiscard]] const EmergencyRuleAuthority &authority() const {
		return _authority;
	}
	[[nodiscard]] const EmergencyRuleDetails &details() const {
		return _details;
	}

private:
	friend EmergencyRuleAuthentication AuthenticateEmergencyRule(
		const EmergencyRuleAuthority&,
		std::span<const uint8_t>,
		std::span<const uint8_t>);

	EmergencyRuleTicket(
		EmergencyRuleAuthority authority,
		EmergencyRuleDetails details)
	: _authority(std::move(authority))
	, _details(std::move(details)) {
	}

	EmergencyRuleAuthority _authority;
	EmergencyRuleDetails _details;

};

[[nodiscard]] size_t SealedEmergencyRulesSize();

[[nodiscard]] std::optional<SealedEmergencyRules> SealEmergencyRules(
	const EmergencyRuleGeneration &generation,
	std::span<const uint8_t> masterDerivedKey,
	const RuleConfiguration &configuration,
	const LiveInstallation &reviewedLive,
	std::span<const EmergencyRuleSealInput> entries);

// The caller must obtain authority independently of the sealed bytes.
[[nodiscard]] EmergencyRuleAuthentication AuthenticateEmergencyRule(
	const EmergencyRuleAuthority &authority,
	std::span<const uint8_t> sealed,
	std::span<const uint8_t> derivedKey);

[[nodiscard]] std::optional<std::vector<NamedEmergencyRule>>
OpenEmergencyRulesForMaster(
	const EmergencyRuleAuthority &authority,
	std::span<const uint8_t> sealed,
	std::span<const uint8_t> masterDerivedKey);

// The emergency passwords must still use the same profile KDF salt and parameters.
[[nodiscard]] std::optional<SealedEmergencyRules> RebindEmergencyRulesForMaster(
	const EmergencyRuleAuthority &previousAuthority,
	std::span<const uint8_t> previousSealed,
	std::span<const uint8_t> previousMasterDerivedKey,
	const EmergencyRuleGeneration &nextGeneration,
	const LiveInstallation &nextLive,
	const EmergencyRuleMasterContext &nextMaster);

} // namespace Ayu::EmergencyActions
