// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_enrollment.h"

#include "ayu/data/ayu_database.h"
#include "ayu/features/profile_sets/profile_account_storage.h"
#include "crl/crl_async.h"
#include "crl/crl_on_main.h"
#include "mtproto/mtproto_config.h"

#include <QtCore/QFileInfo>
#include <openssl/crypto.h>

#include <algorithm>

namespace Ayu::ProfileSets {
namespace {

using Result = ScopedEnrollmentResult;

void Wipe(QByteArray &bytes) {
	OPENSSL_cleanse(bytes.data(), size_t(bytes.size()));
	bytes.clear();
}

void Wipe(DerivedCredential &credential) {
	Wipe(credential.key);
	Wipe(credential.verifier);
}

void WipeKeys(std::vector<AccountKey> &accounts) {
	for (auto &account : accounts) {
		Wipe(account.key);
	}
}

void WipeAccess(ProfileVaultAccess &access) {
	if (const auto master = std::get_if<AdminVaultAccess>(&access)) {
		WipeKeys(master->accounts);
	} else if (const auto set = std::get_if<SetVaultAccess>(&access)) {
		WipeKeys(set->accounts);
		Wipe(set->settingsKey);
	}
}

Result CheckExistingIdentities(
		const QString &root,
		const AdminVaultAccess &master,
		UserId expectedUser) {
	for (const auto &key : master.accounts) {
		const auto locator = std::ranges::find(master.locators, key.id, &AccountVaultLocator::id);
		if (locator == end(master.locators)) {
			return Result::StorageFailed;
		}
		const auto paths = Storage::ScopedAccountPaths(root, AccountVaultDataName(*locator));
		const auto identity = paths
			? Storage::ValidateScopedAccountForStartup(*paths, ProfileAccountStorageKey(key))
			: std::nullopt;
		if (!identity) {
			return Result::StorageFailed;
		} else if (identity->userId == expectedUser) {
			return Result::DuplicateAccount;
		}
	}
	return Result::Complete;
}

bool StageNewAccount(
		const MigrationController &workspace,
		const ScopedEnrollmentRequest &request,
		const AccountKey &key,
		const AccountVaultLocator &locator) {
	const auto name = AccountVaultDataName(locator);
	const auto paths = Storage::ScopedAccountPaths(workspace.accountStorageRoot(), name);
	const auto localKey = ProfileAccountStorageKey(key);
	if (!paths || !localKey || Storage::StageNewScopedAuthorization(
			*paths, localKey, request.userId, request.authorization, request.configuration)
		!= Storage::AccountMigrationResult::Success) {
		return false;
	}
	const auto identity = Storage::ValidateScopedAccountForStartup(*paths, localKey);
	if (!identity || identity->userId != request.userId || identity->environment != request.environment) {
		return false;
	}
	auto archiveKey = std::array<std::byte, kAccountArchiveKeySize>();
	const auto wipe = gsl::finally([&] { OPENSSL_cleanse(archiveKey.data(), archiveKey.size()); });
	if (!DeriveAccountArchiveKey(key, bytes::make_span(archiveKey))) {
		return false;
	}
	const auto archive = LegacyArchiveFileTarget{
		.userId = int64_t(request.userId.bare),
		.locator = name.toStdString(),
		.key = archiveKey,
	};
	const auto data = QFileInfo(QFileInfo(workspace.workspacePath()).path());
	return AyuDatabase::StageEmptyScopedArchivePartitions(data.filesystemFilePath(),
		std::span(&archive, 1)) == ArchivePartitionResult::Success
		&& workspace.SyncScopedAccount(name);
}

Result Enroll(const MigrationController &workspace, ScopedEnrollmentRequest &request) {
	if (!request.userId || !request.targetSet || request.authorization.isEmpty()
		|| request.configuration.isEmpty()) {
		return Result::InvalidAuthorization;
	}
	const auto committed = workspace.LoadCommitted();
	if (!committed || committed->transactionId != request.expectedTransactionId
		|| !committed->legacyRetirement.isEmpty() || !committed->emergencyRecovery.isEmpty()) {
		return Result::Stale;
	} else if (!committed->emergencyRules.isEmpty()) {
		return Result::RuleUpdateRequired;
	}
	const auto vault = ParseProfileVault(committed->profileVault);
	if (!vault || vault->version != kProfileVaultVersion) {
		return Result::StorageFailed;
	}
	auto admin = details::DeriveProfileVaultCredentialOnWorker(vault->salt, vault->kdf, request.masterPasscode);
	auto set = details::DeriveProfileVaultCredentialOnWorker(vault->salt, vault->kdf, request.setPasscode);
	const auto wipeCredentials = gsl::finally([&] { Wipe(admin); Wipe(set); });
	if (!admin.valid() || !set.valid()) {
		return Result::InvalidPasscodes;
	}
	auto access = OpenProfileVault(*vault, admin);
	const auto wipeAccess = gsl::finally([&] { WipeAccess(access); });
	const auto master = std::get_if<AdminVaultAccess>(&access);
	if (!master) {
		return Result::InvalidPasscodes;
	}
	const auto root = workspace.accountStorageRoot();
	const auto checked = CheckExistingIdentities(root, *master, request.userId);
	if (checked != Result::Complete) {
		return checked;
	}
	const auto id = NewAccountId();
	auto key = NewAccountKey(id);
	const auto wipeKey = gsl::finally([&] { if (key) Wipe(key->key); });
	const auto locator = NewAccountVaultLocator(id);
	if (!key || !locator) {
		return Result::StorageFailed;
	}
	const auto enrolled = EnrollProfileVaultAccount(*vault, admin, request.targetSet, set, *key, *locator);
	if (!enrolled) {
		return Result::InvalidPasscodes;
	}
	master->accounts.push_back(*key);
	const auto sealed = SerializeProfileVault(*enrolled);
	const auto keyring = SealAccountKeyring(master->accounts, admin.key);
	if (sealed.isEmpty() || keyring.isEmpty()) {
		return Result::StorageFailed;
	}
	const auto operation = [&] { return StageNewAccount(workspace, request, *key, *locator); };
	auto migrationError = MigrationError::None;
	if (!workspace.WithCurrentGeneration(committed->transactionId, operation, &migrationError)) {
		return migrationError == MigrationError::StaleGeneration ? Result::Stale : Result::StorageFailed;
	}
	const auto published = workspace.ReplaceCommitted(committed->transactionId, {
		{ MigrationArtifact::ProfileVault, sealed }, { MigrationArtifact::AccountKeyring, keyring },
	}, [&](const CommittedMigration &record) {
		return record.profileVault == sealed && record.accountKeyring == keyring
			&& record.emergencyRules.isEmpty() && record.emergencyRecovery.isEmpty();
	}, &migrationError);
	if (published) {
		return workspace.RetireInactiveGenerations(published->transactionId)
			? Result::Complete : Result::Stale;
	}
	return (migrationError == MigrationError::StaleGeneration
		|| migrationError == MigrationError::PublicationUncertain) ? Result::Stale : Result::StorageFailed;
}

} // namespace

void EnrollScopedAccount(
		MigrationController workspace,
		ScopedEnrollmentRequest request,
		Fn<void(ScopedEnrollmentResult)> done) {
	crl::async([workspace = std::move(workspace), request = std::move(request), done = std::move(done)]() mutable {
		const auto result = Enroll(workspace, request);
		request.masterPasscode.fill(QChar(0));
		request.setPasscode.fill(QChar(0));
		Wipe(request.authorization);
		Wipe(request.configuration);
		crl::on_main([done = std::move(done), result]() mutable { done(result); });
	});
}

} // namespace Ayu::ProfileSets
