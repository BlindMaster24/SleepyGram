// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/installation_removal.h"

namespace Ayu::EmergencyActions {

inline constexpr auto kInstallationRemovalHandoffAck = uint8_t('A');
inline constexpr auto kMaxInstallationRemovalHandoffBytes = size_t(9) * 1024 * 1024;

using InstallationRemovalHandoffRead = std::function<
	std::optional<size_t>(std::span<uint8_t>)>;
using InstallationRemovalHandoffWrite = std::function<
	std::optional<size_t>(std::span<const uint8_t>)>;

class InstallationRemovalHandoff final {
public:
	InstallationRemovalHandoff(InstallationRemovalHandoff &&other) noexcept;
	InstallationRemovalHandoff &operator=(InstallationRemovalHandoff&&) = delete;
	~InstallationRemovalHandoff();

	[[nodiscard]] const VerifiedInstallationReceipt &receipt() const;
	[[nodiscard]] const InstallationRemovalTicket &ticket() const;
	[[nodiscard]] std::span<const uint8_t> secret() const;

private:
	friend std::optional<InstallationRemovalHandoff> ReadInstallationRemovalHandoff(
		const InstallationRemovalHandoffRead&);

	InstallationRemovalHandoff(
		VerifiedInstallationReceipt receipt,
		InstallationRemovalTicket ticket,
		std::span<const uint8_t, kInstallationRemovalKeyBytes> secret);

	VerifiedInstallationReceipt _receipt;
	InstallationRemovalTicket _ticket;
	InstallationArtifactDigest _secret{};

};

// I/O callbacks may report short transfers. Reads report zero only at EOF.
[[nodiscard]] bool WriteInstallationRemovalHandoff(
	const VerifiedInstallationReceipt &receipt,
	const InstallationRemovalTicket &ticket,
	std::span<const uint8_t> secret,
	const InstallationRemovalHandoffWrite &write);
[[nodiscard]] std::optional<InstallationRemovalHandoff> ReadInstallationRemovalHandoff(
	const InstallationRemovalHandoffRead &read);

// Only the dedicated helper may use inherited private standard input and output.
[[nodiscard]] InstallationRemovalResult RunInstallationRemovalHandoff(
	const InstallationId &expectedInstallation,
	InstallationRemovalProcessHandle inheritedParent = {},
	std::chrono::milliseconds timeout = std::chrono::seconds(30));

} // namespace Ayu::EmergencyActions
