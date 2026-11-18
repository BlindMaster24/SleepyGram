// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_coordinator.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <functional>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Ayu::EmergencyActions {

using ScopedWebviewStoreId = std::array<uint8_t, 16>;
using ScopedWebviewStoreIds = std::vector<ScopedWebviewStoreId>;
using ClearScopedWebviewStores = std::function<EffectResult(
	std::span<const ScopedWebviewStoreId>)>;

[[nodiscard]] inline bool ValidScopedWebviewStoreIds(
		std::span<const ScopedWebviewStoreId> ids) {
	return ids.size() <= 2
		&& (ids.size() != 2 || ids[0] != ids[1])
		&& std::ranges::none_of(ids, [](const auto &id) {
			return id == ScopedWebviewStoreId();
		});
}

#ifdef __APPLE__
[[nodiscard]] bool BindMacScopedWebviewRecoveryReceipt(
	const InstallationId &installation,
	const OperationId &operation,
	std::string_view admissionGeneration,
	const std::filesystem::path &dataRoot,
	std::span<const uint8_t> encodedReceipt);

[[nodiscard]] bool VerifyMacScopedWebviewRecoveryReceipt(
	const InstallationId &installation,
	const OperationId &operation,
	std::string_view admissionGeneration,
	const std::filesystem::path &dataRoot,
	std::span<const uint8_t> encodedReceipt);

[[nodiscard]] bool RetireMacScopedWebviewRecoveryReceipt(
	const InstallationId &installation,
	const OperationId &operation,
	std::string_view admissionGeneration,
	const std::filesystem::path &dataRoot,
	std::span<const uint8_t> encodedReceipt);

[[nodiscard]] EffectResult ClearMacScopedWebviewStores(
	std::span<const ScopedWebviewStoreId> ids);
#endif

struct ScopedAccountLocator final {
	AccountId accountId;
	std::string locator;
	std::optional<ScopedWebviewStoreIds> namedWebviewStores;
};

struct ScopedAccountCleanupBinding final {
	InstallationId installationId;
	std::filesystem::path accountStorageRoot;
	std::vector<ScopedAccountLocator> accounts;
};

class ScopedAccountClear final : public LocalAccountEffect {
public:
	// The caller must authenticate the binding, stop account writers and retire the vault keys.
	ScopedAccountClear(
		const InstallationId &installationId,
		std::filesystem::path installationDataDirectory,
		ScopedAccountCleanupBinding authenticatedBinding,
		ClearScopedWebviewStores clearNamedStores = {});

	[[nodiscard]] EffectResult clear(const AccountId &accountId) override;

private:
	const std::filesystem::path _accountStorageRoot;
	const std::vector<ScopedAccountLocator> _accounts;
	const ClearScopedWebviewStores _clearNamedStores;
	std::set<AccountId> _confirmedNamedClears;
	bool _valid = false;

};

} // namespace Ayu::EmergencyActions
