// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_staging.h"

#include "ayu/ayu_preferences_migration.h"
#include "ayu/data/archive_migration.h"
#include "ayu/data/ayu_database.h"
#include "ayu/features/offline_history/offline_history_scoped.h"
#include "ayu/features/profile_sets/profile_migration.h"
#include "storage/storage_domain.h"
#include "wallet/wallet_profile_migration_storage.h"

#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <openssl/crypto.h>

#include <array>
#include <map>
#include <set>
#include <vector>

namespace Ayu::ProfileSets {
namespace {

ProfileStagingResult StageWhilePreparing(
		const MigrationController &workspace,
		const QString &dataDirectory,
		const QString &dataName,
		const QByteArray &legacyPasscode,
		std::span<const ProfileStagingAccount> accounts,
		const QByteArray &transactionId,
		LegacyRetirementPlan *retirement,
		const Preferences::LegacyPartition *preferences,
		Storage::LegacyWebviewTransfer webview,
		const Wallet::SecureBytes *legacyWalletPasscode) {
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
	using WalletState = Wallet::LegacyWalletProfileRingReading::State;
	auto wallet = Wallet::ReadLegacyWalletProfileRing(
		root, dataName, legacy->localKey, legacyWalletPasscode);
	if (wallet.state == WalletState::WalletPasscodeRequired) {
		return Result::LegacyWalletPasscodeRequired;
	} else if (wallet.state == WalletState::WalletPasscodeRejected) {
		return Result::LegacyWalletPasscodeRejected;
	} else if (wallet.state != WalletState::Absent && wallet.state != WalletState::Ready) {
		return Result::UnsupportedAccountData;
	}
	auto walletFiles = std::vector<LegacyRetirementEntry>();
	auto walletAccounts = std::vector<Storage::LegacyWalletAccountInventory>();
	auto walletTargets = std::map<quint64, Wallet::ScopedProfileMigrationWallet>();
	const auto walletFactor = (wallet.unlocked
		&& wallet.unlocked->keyring.wrap.kind == Wallet::VaultKind::Passcode)
		? legacyWalletPasscode
		: nullptr;
	if (wallet.unlocked) {
		for (const auto &proof : wallet.unlocked->files) {
			walletFiles.push_back({ proof.relativePath, proof.sha256 });
		}
		walletAccounts.reserve(accounts.size());
		auto privateWallets = std::vector<Wallet::ProfileMigrationWalletAccount>();
		for (const auto &account : accounts) {
			const auto source = Storage::AccountPathsForDataName(
				root, Storage::AccountDataName(dataName, account.slot));
			auto inventory = Storage::ReadLegacyWalletAccountInventory(
				source, legacy->localKey, account.userId, webview);
			if (!inventory) {
				return Result::UnsupportedAccountData;
			}
			for (const auto &proof : inventory->files) {
				walletFiles.push_back({ proof.relativePath, proof.sha256 });
			}
			const auto &stored = walletAccounts.emplace_back(std::move(*inventory));
			if (!stored.secretRecords.empty()) {
				privateWallets.push_back({
					.owner = stored.owner,
					.custodySecretRefs = stored.custodyRefs,
					.secretRecords = stored.secretRecords,
					.destinationPasscode = walletFactor,
				});
			}
		}
		if (!privateWallets.empty() || !wallet.unlocked->keyring.entries.empty()) {
			auto planned = Wallet::PlanProfileWalletMigration(
				wallet.unlocked->keyring, wallet.unlocked->deviceKey, privateWallets);
			if (!planned) {
				return Result::UnsupportedAccountData;
			}
			for (auto &target : *planned) {
				const auto owner = target.owner;
				walletTargets.emplace(owner, std::move(target));
			}
		}
	}
	auto verifiedAccounts = std::vector<VerifiedLegacyRetirementAccount>();
	auto offlineAccounts = std::vector<OfflineHistory::ScopedOfflineAccount>();
	auto walletDeviceKeys = std::set<QByteArray>();
	for (auto i = size_t(0); i != accounts.size(); ++i) {
		const auto &account = accounts[i];
		const auto source = Storage::AccountPathsForDataName(root,
			Storage::AccountDataName(dataName, account.slot));
		auto transfer = std::optional<Storage::LegacyWalletAccountTransfer>();
		if (wallet.unlocked && !walletAccounts[i].secretRecords.empty()) {
			const auto &inventory = walletAccounts[i];
			const auto target = walletTargets.find(inventory.owner);
			if (target == end(walletTargets)) {
				return Result::AccountStageFailed;
			}
			transfer.emplace(Storage::LegacyWalletAccountTransfer{
				.source = inventory,
				.destination = target->second,
				.oldDeviceKey = wallet.unlocked->deviceKey,
				.walletPasscode = walletFactor,
			});
		}
		auto files = Storage::VerifiedLegacyAccountFiles();
		const auto stage = StageProfileAccount(
			workspace, source, legacy->localKey, account.userId,
			account.key, account.locator, (retirement || transfer) ? &files : nullptr,
			webview, transfer ? &*transfer : nullptr);
		if (stage != Storage::AccountMigrationResult::Success) {
			return (stage == Storage::AccountMigrationResult::UnsupportedData)
				? Result::UnsupportedAccountData
				: Result::AccountStageFailed;
		}
		if (transfer && (files.walletDeviceKeySha256.size() != 32
			|| !walletDeviceKeys.emplace(std::move(files.walletDeviceKeySha256)).second)) {
			return Result::AccountStageFailed;
		}
		if (preferences || retirement) {
			const auto user = account.userId.bare;
			const auto directory = QDir(workspace.accountStorageRoot()).filePath(
				AccountVaultDataName(account.locator));
			const auto key = ProfileAccountStorageKey(account.key);
			if (preferences) {
				const auto payload = preferences->accounts.find(user);
				if (payload == end(preferences->accounts)
					|| !Preferences::StageScopedAccountPreferences(directory, user, key, payload->second)) {
					return Result::AccountStageFailed;
				}
			}
			if (retirement) {
				offlineAccounts.push_back({ .userId = user, .accountRoot = directory, .key = key });
			}
		}
		if (retirement) {
			verifiedAccounts.push_back({
				.index = account.slot,
				.paths = source,
				.dataFiles = std::move(files.dataFiles),
				.tgwFiles = std::move(files.tgwFiles),
				.cacheDirectories = std::move(files.cacheDirectories),
				.cacheFiles = std::move(files.cacheFiles),
			});
		}
	}
	const auto utf8 = root.toUtf8();
	const auto path = std::filesystem::path(std::u8string(
		reinterpret_cast<const char8_t*>(utf8.constData()), utf8.size()));
	const auto legacyArchive = QFileInfo(root + u"/ayudata.db"_q);
	const auto hasArchive = legacyArchive.exists()
		|| legacyArchive.isSymLink() || legacyArchive.isJunction();
	const auto archiveResult = hasArchive
		? AyuDatabase::StageLegacyArchivePartitions(path, archives)
		: AyuDatabase::StageEmptyScopedArchivePartitions(path, archives);
	if (archiveResult != ArchivePartitionResult::Success) {
		return Result::ArchiveStageFailed;
	}
	if (retirement) {
		const auto offline = OfflineHistory::StageLegacyOfflineHistory(root, offlineAccounts);
		if (!offline) {
			return Result::UnsupportedAccountData;
		}
		const auto archive = hasArchive
			? LegacyArchiveRetirement::VerifiedPartitioned
			: LegacyArchiveRetirement::ExpectedAbsent;
		auto captured = CaptureLegacyRetirementPlan(
			root, dataName, transactionId, legacy->accountIndices,
			verifiedAccounts, archive,
			preferences ? preferences->sourceSha256 : QByteArray(), *offline, webview, &walletFiles);
		if (!captured) {
			return Result::RetirementVerificationFailed;
		}
		*retirement = std::move(*captured);
	}
	return Result::Success;
}

} // namespace

ProfileStagingResult StageScopedProfileData(
		const MigrationController &workspace,
		const QString &dataDirectory,
		const QString &dataName,
		const QByteArray &legacyPasscode,
		std::span<const ProfileStagingAccount> accounts,
		const QByteArray &transactionId,
		LegacyRetirementPlan *retirement,
		const Preferences::LegacyPartition *preferences,
		Storage::LegacyWebviewTransfer webview,
		const Wallet::SecureBytes *legacyWalletPasscode) {
	auto staged = ProfileStagingResult::InvalidWorkspace;
	const auto verify = [&] {
		staged = StageWhilePreparing(
			workspace, dataDirectory, dataName, legacyPasscode, accounts,
			transactionId, retirement, preferences, webview, legacyWalletPasscode);
		return staged == ProfileStagingResult::Success;
	};
	const auto ran = (!transactionId.isEmpty() && workspace.LoadStaged())
		? workspace.WithStagedSetup(transactionId, verify)
		: workspace.WithPreparingWorkspace(verify);
	return ran ? ProfileStagingResult::Success : staged;
}

} // namespace Ayu::ProfileSets
