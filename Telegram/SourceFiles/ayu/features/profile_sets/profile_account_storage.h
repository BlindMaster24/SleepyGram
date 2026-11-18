/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ayu/features/profile_sets/profile_vault.h"
#include "storage/storage_account.h"

namespace Ayu::ProfileSets {

class MigrationController;

[[nodiscard]] MTP::AuthKeyPtr ProfileAccountStorageKey(const AccountKey &key);
[[nodiscard]] MTP::AuthKeyPtr ProfileSettingsStorageKey(const QByteArray &key);

[[nodiscard]] Storage::AccountMigrationResult StageProfileAccount(
	const MigrationController &workspace,
	const Storage::AccountPaths &legacy,
	const MTP::AuthKeyPtr &legacyKey,
	UserId expectedUser,
	const AccountKey &account,
	const AccountVaultLocator &locator,
	Storage::VerifiedLegacyAccountFiles *verifiedFiles = nullptr,
	Storage::LegacyWebviewTransfer webview = Storage::LegacyWebviewTransfer::RequireIsolated);

} // namespace Ayu::ProfileSets
