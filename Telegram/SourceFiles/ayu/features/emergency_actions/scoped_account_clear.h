// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/emergency_action_coordinator.h"

#include <filesystem>
#include <string>
#include <vector>

namespace Ayu::EmergencyActions {

struct ScopedAccountLocator final {
	AccountId accountId;
	std::string locator;
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
		ScopedAccountCleanupBinding authenticatedBinding);

	[[nodiscard]] EffectResult clear(const AccountId &accountId) override;

private:
	const std::filesystem::path _accountStorageRoot;
	const std::vector<ScopedAccountLocator> _accounts;
	bool _valid = false;

};

} // namespace Ayu::EmergencyActions
