// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_journal.h"
#include "ayu/features/emergency_actions/installation_removal.h"

#include <future>

namespace Ayu::EmergencyActions {

struct VerifiedInstallationRemovalHelper final {
	std::filesystem::path source;
	InstallationArtifactDigest digest{};
};

enum class InstallationRemovalLaunchResult : uint8_t {
	ReadyToExit,
	Rejected,
	HelperUnavailable,
	TransportFailed,
	AcknowledgmentUnconfirmed,
};

// The caller supplies an independently verified helper digest and a durable cleanup journal.
[[nodiscard]] std::future<InstallationRemovalLaunchResult> LaunchInstallationRemoval(
	VerifiedInstallationRemovalHelper helper,
	VerifiedInstallationReceipt receipt,
	EmergencyActionJournal completedCleanup,
	std::chrono::milliseconds timeout = std::chrono::seconds(30));

} // namespace Ayu::EmergencyActions
