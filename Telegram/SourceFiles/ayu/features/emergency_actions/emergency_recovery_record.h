// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_journal.h"
#include "ayu/features/emergency_actions/emergency_execution_capsule.h"
#include "ayu/features/emergency_actions/scoped_account_clear.h"

#include <string_view>

namespace Ayu::EmergencyActions {

inline constexpr auto kMaxEmergencyRecoveryRecordBytes = size_t(80) * 1024 * 1024;

enum class EmergencyRecoveryPhase : uint8_t {
	Admission,
	Successor,
};

struct PreparedEmergencyRecoveryRecord final {
	std::vector<uint8_t> bytes;
	OpenedEmergencyExecutionCapsule capsule;
};

struct EmergencyRecoveryRecord final {
	EmergencyRecoveryPhase phase = EmergencyRecoveryPhase::Admission;
	std::string sourceGeneration;
	std::string admissionGeneration;
	std::string successorGeneration;
	EmergencyActionJournal journal;
	std::vector<ScopedAccountLocator> accounts;
	std::vector<uint8_t> sealedProfileVault;
	std::vector<uint8_t> sealedAccountKeyring;
	std::vector<uint8_t> installationDigest;
};

[[nodiscard]] std::optional<PreparedEmergencyRecoveryRecord> PrepareEmergencyRecoveryRecord(
	const EmergencyRuleTicket &ticket,
	std::span<const uint8_t> sealedCapsule,
	std::span<const uint8_t> emergencyDerivedKey,
	std::string_view admissionGeneration);

// The caller must supply bytes from an independently verified committed artifact.
[[nodiscard]] std::optional<EmergencyRecoveryRecord> DecodeEmergencyRecoveryRecord(
	std::span<const uint8_t> bytes,
	const InstallationId &expectedInstallation,
	std::string_view activeGeneration);

// This verifies immutable plan data only; checkpoint progress needs its own trust.
[[nodiscard]] bool MatchesEmergencyRecoveryJournal(
	const EmergencyRecoveryRecord &record,
	const EmergencyActionJournal &checkpoint);

} // namespace Ayu::EmergencyActions
