// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/profile_account_storage.h"

#include <span>

namespace Ayu::ProfileSets {

struct ProfileStagingAccount final {
	int slot = -1;
	UserId userId;
	AccountKey key;
	AccountVaultLocator locator;
};

enum class ProfileStagingResult {
	Success,
	InvalidWorkspace,
	InvalidLegacyProfile,
	InvalidBindings,
	UnsupportedAccountData,
	AccountStageFailed,
	ArchiveStageFailed,
};

// The caller keeps the original profile and scoped workspace closed to writers.
[[nodiscard]] ProfileStagingResult StageScopedProfileData(
	const MigrationController &workspace,
	const QString &dataDirectory,
	const QString &dataName,
	const QByteArray &legacyPasscode,
	std::span<const ProfileStagingAccount> accounts);

} // namespace Ayu::ProfileSets
