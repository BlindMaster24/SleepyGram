/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_account_storage.h"

#include "ayu/features/profile_sets/profile_migration.h"
#include "mtproto/mtproto_auth_key.h"

#include <openssl/crypto.h>

namespace Ayu::ProfileSets {

MTP::AuthKeyPtr ProfileAccountStorageKey(const AccountKey &key) {
	static_assert(MTP::AuthKey::kSize == kAccountLocalStorageKeySize);
	auto material = MTP::AuthKey::Data();
	const auto wipe = gsl::finally([&] {
		OPENSSL_cleanse(material.data(), material.size());
	});
	return DeriveAccountLocalStorageKey(key, bytes::make_span(material))
		? std::make_shared<MTP::AuthKey>(material)
		: nullptr;
}

Storage::AccountMigrationResult StageProfileAccount(
		const MigrationController &workspace,
		const Storage::AccountPaths &legacy,
		const MTP::AuthKeyPtr &legacyKey,
		UserId expectedUser,
		const AccountKey &account,
		const AccountVaultLocator &locator) {
	using Result = Storage::AccountMigrationResult;
	if (workspace.isIsolatedFixture() || account.id != locator.id) {
		return Result::InvalidPaths;
	}
	const auto paths = Storage::ScopedAccountPaths(
		workspace.accountStorageRoot(), AccountVaultDataName(locator));
	const auto key = ProfileAccountStorageKey(account);
	return !paths
		? Result::InvalidPaths
		: Storage::StageLegacyAccount(legacy, legacyKey, *paths, key, expectedUser);
}

} // namespace Ayu::ProfileSets
