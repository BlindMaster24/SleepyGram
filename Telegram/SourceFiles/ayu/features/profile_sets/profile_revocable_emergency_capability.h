// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_execution_capsule.h"
#include "ayu/features/profile_sets/account_gate_table.h"

#include <array>
#include <memory>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace Ayu::ProfileSets {

inline constexpr auto kRevocableEmergencyCapabilityMagic
	= std::array<uint8_t, 8>{ 'S', 'G', 'E', 'C', 0, 0, 0, 3 };

struct RevocableEmergencyAccount final {
	AccountGateHandle handle;
	AccountGateRevocationPermit permit;
	std::optional<EmergencyActions::EmergencyScopedRemoteIdentity> remoteIdentity;
};

struct RevocableEmergencySafeSetView final {
	SetId id;
	QByteArrayView verifier;
	QByteArrayView key;
};

struct InvalidRevocableEmergencyCapability final {};

struct RevokedRevocableEmergencyTargets final {
	std::vector<AccountId> accounts;
};

class OpenedRevocableEmergencyCapability;

using RevocableEmergencyCapabilityOpenResult = std::variant<
	InvalidRevocableEmergencyCapability,
	RevokedRevocableEmergencyTargets,
	OpenedRevocableEmergencyCapability>;

enum class RevocableEmergencyTargets {
	Active,
	Reviewed,
};

class OpenedRevocableEmergencyCapability final {
public:
	OpenedRevocableEmergencyCapability(OpenedRevocableEmergencyCapability&&) noexcept;
	~OpenedRevocableEmergencyCapability();

	[[nodiscard]] const EmergencyActions::DryRunPlan &plan() const;
	[[nodiscard]] const std::vector<RevocableEmergencyAccount> &accounts() const;
	[[nodiscard]] std::vector<RevocableEmergencyAccount> takeAccounts() &&;
	// Credential views borrow this object's authenticated plaintext.
	[[nodiscard]] const std::optional<RevocableEmergencySafeSetView> &safeSet() const;
	[[nodiscard]] auto packageDigest() const
	-> const std::optional<EmergencyActions::EmergencyExecutionCapsuleDigest>&;

private:
	friend RevocableEmergencyCapabilityOpenResult OpenRevocableEmergencyCapabilityForRebind(
		const EmergencyActions::EmergencyRuleGeneration&,
		const EmergencyActions::EmergencyRuleTicket&,
		const AccountGateTable&,
		std::span<const uint8_t>,
		const std::optional<EmergencyActions::EmergencyExecutionCapsuleDigest>&,
		EmergencyActions::EmergencyExecutionCapsuleKey,
		RevocableEmergencyTargets);

	struct Data;
	explicit OpenedRevocableEmergencyCapability(std::unique_ptr<Data> data);

	std::unique_ptr<Data> _data;

};

[[nodiscard]] std::optional<EmergencyActions::SealedEmergencyExecutionCapsule>
SealRevocableEmergencyCapability(
	const EmergencyActions::EmergencyRuleGeneration &ruleEpoch,
	const EmergencyActions::EmergencyRuleDetails &details,
	const EmergencyActions::LiveInstallation &reviewedLive,
	const AccountGateTable &gates,
	std::span<const RevocableEmergencyAccount> accounts,
	const std::optional<RevocableEmergencySafeSetView> &safeSet,
	const std::optional<EmergencyActions::EmergencyExecutionCapsuleDigest> &packageDigest,
	std::span<const uint8_t> emergencyDerivedKey);

[[nodiscard]] std::optional<EmergencyActions::SealedEmergencyExecutionCapsule>
SealRevocableEmergencyCapabilityForRebind(
	const EmergencyActions::EmergencyRuleGeneration &ruleEpoch,
	const EmergencyActions::EmergencyRuleDetails &details,
	const EmergencyActions::LiveInstallation &reviewedLive,
	const AccountGateTable &gates,
	std::span<const RevocableEmergencyAccount> accounts,
	const std::optional<RevocableEmergencySafeSetView> &safeSet,
	const std::optional<EmergencyActions::EmergencyExecutionCapsuleDigest> &packageDigest,
	EmergencyActions::EmergencyExecutionCapsuleKey capsuleKey,
	RevocableEmergencyTargets targets = RevocableEmergencyTargets::Active);

// The epoch, table and removal package digest come from the current installation.
[[nodiscard]] RevocableEmergencyCapabilityOpenResult OpenRevocableEmergencyCapability(
	const EmergencyActions::EmergencyRuleGeneration &expectedRuleEpoch,
	const EmergencyActions::EmergencyRuleTicket &ticket,
	const AccountGateTable &gates,
	std::span<const uint8_t> sealed,
	const std::optional<EmergencyActions::EmergencyExecutionCapsuleDigest> &expectedPackageDigest,
	std::span<const uint8_t> emergencyDerivedKey);

[[nodiscard]] RevocableEmergencyCapabilityOpenResult OpenRevocableEmergencyCapabilityForRebind(
	const EmergencyActions::EmergencyRuleGeneration &expectedRuleEpoch,
	const EmergencyActions::EmergencyRuleTicket &ticket,
	const AccountGateTable &gates,
	std::span<const uint8_t> sealed,
	const std::optional<EmergencyActions::EmergencyExecutionCapsuleDigest> &expectedPackageDigest,
	EmergencyActions::EmergencyExecutionCapsuleKey capsuleKey,
	RevocableEmergencyTargets targets = RevocableEmergencyTargets::Active);

} // namespace Ayu::ProfileSets
