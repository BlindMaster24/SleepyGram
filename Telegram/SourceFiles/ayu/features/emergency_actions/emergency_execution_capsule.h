// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_rule_vault.h"

#include <memory>
#include <span>

namespace Ayu::EmergencyActions {

inline constexpr auto kEmergencyExecutionScopedKeyBytes = size_t(32);
inline constexpr auto kMaxEmergencyExecutionAccounts = size_t(64);
inline constexpr auto kMaxEmergencyExecutionSuccessorVaultBytes = size_t(80) * 1024 * 1024;
inline constexpr auto kMaxEmergencyExecutionSuccessorKeyringBytes = size_t(4) * 1024 * 1024;
inline constexpr auto kMaxEmergencyExecutionSafeGrantBytes = size_t(4) * 1024 * 1024;
inline constexpr auto kEmergencyInstallationDigestBytes = size_t(32);

enum class EmergencyScopedEnvironment : uint8_t {
	Production = 1,
	Test = 2,
};

struct EmergencyScopedRemoteIdentity final {
	uint64_t userId = 0;
	EmergencyScopedEnvironment environment = EmergencyScopedEnvironment::Production;
};

struct EmergencyExecutionAccount final {
	AccountId accountId;
	std::string locator;
	std::span<const uint8_t> scopedKey;
	std::optional<EmergencyScopedRemoteIdentity> remoteIdentity;
};

struct EmergencyExecutionSuccessor final {
	std::string transactionId;
	std::span<const uint8_t> sealedProfileVault;
	std::span<const uint8_t> sealedAccountKeyring;
	std::span<const uint8_t> installationDigest;
};

struct EmergencyExecutionSafeDestination final {
	ProfileId profileId;
	std::span<const uint8_t> sealedSetGrant;
};

struct SealedEmergencyExecutionCapsule final {
	std::vector<uint8_t> bytes;
	EmergencyExecutionCapsuleDigest digest{};
};

class OpenedEmergencyExecutionCapsule final {
public:
	OpenedEmergencyExecutionCapsule(OpenedEmergencyExecutionCapsule&&) noexcept;
	OpenedEmergencyExecutionCapsule &operator=(OpenedEmergencyExecutionCapsule&&) noexcept;
	~OpenedEmergencyExecutionCapsule();

	[[nodiscard]] std::span<const EmergencyExecutionAccount> accounts() const;
	[[nodiscard]] const EmergencyExecutionSuccessor &successor() const;
	[[nodiscard]] const std::optional<EmergencyExecutionSafeDestination> &safeDestination() const;

private:
	friend std::optional<OpenedEmergencyExecutionCapsule> OpenEmergencyExecutionCapsule(
		const EmergencyRuleTicket&,
		const DryRunPlan&,
		std::span<const uint8_t>,
		std::span<const uint8_t>);

	struct Data;
	explicit OpenedEmergencyExecutionCapsule(std::unique_ptr<Data> data);

	std::unique_ptr<Data> _data;

};

[[nodiscard]] size_t MaximumEmergencyExecutionCapsuleSize();

[[nodiscard]] std::optional<SealedEmergencyExecutionCapsule> SealEmergencyExecutionCapsule(
	const EmergencyRuleGeneration &generation,
	const EmergencyRuleDetails &details,
	const DryRunPlan &plan,
	std::span<const EmergencyExecutionAccount> accounts,
	const EmergencyExecutionSuccessor &successor,
	const std::optional<EmergencyExecutionSafeDestination> &safeDestination,
	std::span<const uint8_t> emergencyDerivedKey);

// References and key spans are valid only while the opened capsule remains alive.
[[nodiscard]] std::optional<OpenedEmergencyExecutionCapsule> OpenEmergencyExecutionCapsule(
	const EmergencyRuleTicket &ticket,
	const DryRunPlan &plan,
	std::span<const uint8_t> sealed,
	std::span<const uint8_t> emergencyDerivedKey);

} // namespace Ayu::EmergencyActions
