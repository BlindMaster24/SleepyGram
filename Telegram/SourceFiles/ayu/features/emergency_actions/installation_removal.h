// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_plan.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>

namespace Ayu::EmergencyActions {

struct EmergencyActionJournal;

enum class InstallationPackageKind : uint8_t {
	Unknown,
	LinuxPortable,
	WindowsPortable,
	MacBundle,
	RegisteredPackage,
};

enum class InstallationRemovalCapability : uint8_t {
	Unavailable,
	OsConfirmationRequired,
	Automatic,
};

enum class InstallationRemovalResult : uint8_t {
	Removed,
	Partial,
	Unavailable,
	TicketRejected,
	ParentUnavailable,
	ParentStillRunning,
	InstallationChanged,
	RefusalNotRecorded,
};

inline constexpr auto kInstallationRemovalKeyBytes = size_t(32);
inline constexpr auto kMaxInstallationRemovalDataBytes = size_t(2) * 1024 * 1024;
using InstallationArtifactDigest = std::array<uint8_t, kInstallationRemovalKeyBytes>;

struct VerifiedInstallationArtifact final {
	std::filesystem::path relativePath;
	InstallationArtifactDigest digest;
};

struct VerifiedInstallationReceipt final {
	InstallationId installationId;
	InstallationPackageKind kind = InstallationPackageKind::Unknown;
	std::filesystem::path packageRoot;
	std::vector<VerifiedInstallationArtifact> artifacts;
	std::vector<uint8_t> dataCleanup;
};

struct InstallationRemovalTicket final {
	OperationId operationId;
	uint64_t parentProcessId = 0;
	InstallationArtifactDigest authentication{};
	uint64_t parentCreationTime = 0;
};

struct InstallationRemovalProcessHandle final {
	uintptr_t value = 0;
};

struct InstallationRemovalDataEffects final {
	std::function<bool()> clear;
	std::function<bool()> finalize;
	std::function<bool()> refuse;
};

[[nodiscard]] InstallationRemovalCapability InspectInstallationRemoval(
	const VerifiedInstallationReceipt &receipt);

// Both ends use a fresh secret from the private handoff. A receipt requires independent package verification.
[[nodiscard]] std::optional<InstallationRemovalTicket> MakeInstallationRemovalTicket(
	const VerifiedInstallationReceipt &receipt,
	const EmergencyActionJournal &completedCleanup,
	std::span<const uint8_t> handoffSecret);

class InstallationRemovalReceiver final {
public:
	InstallationRemovalReceiver() = default;
	InstallationRemovalReceiver(const InstallationRemovalReceiver&) = delete;
	InstallationRemovalReceiver &operator=(const InstallationRemovalReceiver&) = delete;

	// On Windows the private-channel launcher supplies a borrowed inherited process handle.
	[[nodiscard]] InstallationRemovalResult RemoveAfterParentExit(
		const InstallationId &expectedInstallation,
		const VerifiedInstallationReceipt &receipt,
		const InstallationRemovalTicket &ticket,
		std::span<const uint8_t> handoffSecret,
		std::chrono::milliseconds timeout,
		const std::function<bool()> &acknowledge,
		InstallationRemovalProcessHandle inheritedParent = {},
		const InstallationRemovalDataEffects &dataEffects = {});

private:
	std::atomic_bool _used = false;

};

} // namespace Ayu::EmergencyActions
