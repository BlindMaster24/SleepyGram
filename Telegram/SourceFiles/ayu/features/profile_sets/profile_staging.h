// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/profile_account_storage.h"
#include "ayu/features/profile_sets/legacy_retirement.h"

#include <span>

namespace Ayu::Preferences {
struct LegacyPartition;
} // namespace Ayu::Preferences

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
	LegacyWalletPasscodeRequired,
	LegacyWalletPasscodeRejected,
	UnsupportedAccountData,
	AccountStageFailed,
	ArchiveStageFailed,
	RetirementVerificationFailed,
};

// The caller keeps the original profile and scoped workspace closed to writers.
[[nodiscard]] ProfileStagingResult StageScopedProfileData(
	const MigrationController &workspace,
	const QString &dataDirectory,
	const QString &dataName,
	const QByteArray &legacyPasscode,
	std::span<const ProfileStagingAccount> accounts,
	const QByteArray &transactionId = {},
	LegacyRetirementPlan *retirement = nullptr,
	const Preferences::LegacyPartition *preferences = nullptr,
	Storage::LegacyWebviewTransfer webview = Storage::LegacyWebviewTransfer::RequireIsolated,
	const Wallet::SecureBytes *legacyWalletPasscode = nullptr);

} // namespace Ayu::ProfileSets
