// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_staging.h"

#include "ayu/data/archive_migration.h"
#include "ayu/data/ayu_database.h"
#include "ayu/features/profile_sets/profile_migration.h"
#include "storage/storage_domain.h"

#include <QtCore/QDir>
#include <openssl/crypto.h>

#include <array>
#include <set>
#include <vector>

namespace Ayu::ProfileSets {
namespace {

ProfileStagingResult StageWhilePreparing(
		const MigrationController &workspace,
		const QString &dataDirectory,
		const QString &dataName,
		const QByteArray &legacyPasscode,
		std::span<const ProfileStagingAccount> accounts) {
	using Result = ProfileStagingResult;
	const auto root = QDir::cleanPath(dataDirectory);
	if (workspace.accountStorageRoot() != root + u"/profile-sets/accounts"_q) {
		return Result::InvalidWorkspace;
	}
	const auto legacy = Storage::ReadLegacyProfileInventory(
		root, dataName, legacyPasscode);
	if (!legacy) {
		return Result::InvalidLegacyProfile;
	}
	if (legacy->accountIndices.size() != accounts.size()) {
		return Result::InvalidBindings;
	}
	auto remainingSlots = std::set<int>(
		legacy->accountIndices.begin(), legacy->accountIndices.end());
	auto users = std::set<UserId>();
	auto ids = std::set<AccountId>();
	auto locators = std::set<QString>();
	using ArchiveKey = std::array<std::byte, kAccountArchiveKeySize>;
	auto keys = std::vector<ArchiveKey>(accounts.size());
	const auto wipeKeys = gsl::finally([&] {
		for (auto &key : keys) {
			OPENSSL_cleanse(key.data(), key.size());
		}
	});
	auto archives = std::vector<LegacyArchiveFileTarget>();
	archives.reserve(accounts.size());
	for (auto i = size_t(0); i != accounts.size(); ++i) {
		const auto &account = accounts[i];
		const auto locator = AccountVaultDataName(account.locator);
		if (remainingSlots.erase(account.slot) != 1 || !account.userId
			|| !users.insert(account.userId).second
			|| account.key.id != account.locator.id
			|| !ids.insert(account.key.id).second
			|| locator.isEmpty() || !locators.insert(locator).second
			|| !DeriveAccountArchiveKey(account.key, bytes::make_span(keys[i]))) {
			return Result::InvalidBindings;
		}
		archives.push_back({
			.userId = int64_t(account.userId.bare & PeerId::kChatTypeMask),
			.locator = locator.toStdString(),
			.key = keys[i],
		});
	}
	for (const auto &account : accounts) {
		const auto source = Storage::AccountPathsForDataName(root,
			Storage::AccountDataName(dataName, account.slot));
		const auto stage = StageProfileAccount(
			workspace, source, legacy->localKey, account.userId,
			account.key, account.locator);
		if (stage != Storage::AccountMigrationResult::Success) {
			return (stage == Storage::AccountMigrationResult::UnsupportedData)
				? Result::UnsupportedAccountData
				: Result::AccountStageFailed;
		}
	}
	const auto utf8 = root.toUtf8();
	const auto path = std::filesystem::path(std::u8string(
		reinterpret_cast<const char8_t*>(utf8.constData()), utf8.size()));
	return (AyuDatabase::StageLegacyArchivePartitions(path, archives)
		== ArchivePartitionResult::Success)
		? Result::Success
		: Result::ArchiveStageFailed;
}

} // namespace

ProfileStagingResult StageScopedProfileData(
		const MigrationController &workspace,
		const QString &dataDirectory,
		const QString &dataName,
		const QByteArray &legacyPasscode,
		std::span<const ProfileStagingAccount> accounts) {
	auto staged = ProfileStagingResult::InvalidWorkspace;
	const auto ran = workspace.WithPreparingWorkspace([&] {
		staged = StageWhilePreparing(
			workspace, dataDirectory, dataName, legacyPasscode, accounts);
		return staged == ProfileStagingResult::Success;
	});
	return ran ? ProfileStagingResult::Success : staged;
}

} // namespace Ayu::ProfileSets
