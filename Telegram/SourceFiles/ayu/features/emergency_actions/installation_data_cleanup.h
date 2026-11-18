// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/installation_removal.h"

namespace Ayu::EmergencyActions {

inline constexpr auto kMaxInstallationDataCleanupFiles = size_t(4096);
inline constexpr auto kMaxInstallationDataCleanupPlanBytes = size_t(2) * 1024 * 1024;

struct InstallationDataIdentity final {
	uint64_t volume = 0;
	uint64_t node = 0;

	friend bool operator==(const InstallationDataIdentity&, const InstallationDataIdentity&) = default;
};

struct InstallationDataCleanupFile final {
	std::string relativePath;
	InstallationDataIdentity identity;
	InstallationArtifactDigest digest{};

	friend bool operator==(const InstallationDataCleanupFile&, const InstallationDataCleanupFile&) = default;
};

struct InstallationDataCleanupScope final {
	InstallationId installationId;
	std::filesystem::path dataDirectory;
	std::vector<std::string> setIds;
	std::vector<std::string> generationIds;
	std::vector<OperationId> journalIds;
};

struct InstallationDataCleanupPlan final {
	InstallationId installationId;
	std::filesystem::path dataDirectory;
	InstallationDataIdentity rootIdentity;
	std::vector<InstallationDataCleanupFile> files;
};

enum class InstallationDataCleanupPhase : uint8_t {
	AfterExit,
	FinalizeRecovery,
};

enum class InstallationDataCleanupResult : uint8_t {
	Complete,
	InvalidPlan,
	UnexpectedFile,
	FilesystemFailure,
	NormalFilesRemain,
};

// Capture only after closing writers and releasing the recovery/workspace locks.
[[nodiscard]] std::optional<InstallationDataCleanupPlan> CaptureInstallationDataCleanupPlan(
	const InstallationDataCleanupScope &scope);
[[nodiscard]] bool ValidateInstallationDataCleanupPlan(const InstallationDataCleanupPlan &plan);
[[nodiscard]] std::vector<uint8_t> EncodeInstallationDataCleanupPlan(
	const InstallationDataCleanupPlan &plan);
[[nodiscard]] std::optional<InstallationDataCleanupPlan> DecodeInstallationDataCleanupPlan(
	std::span<const uint8_t> bytes);

// The helper must wait for the authenticated parent and validate the handoff first.
[[nodiscard]] InstallationDataCleanupResult ClearInstallationDataFiles(
	const InstallationId &expectedInstallation,
	const std::filesystem::path &expectedTdata,
	const InstallationDataCleanupPlan &plan,
	InstallationDataCleanupPhase phase);

} // namespace Ayu::EmergencyActions
