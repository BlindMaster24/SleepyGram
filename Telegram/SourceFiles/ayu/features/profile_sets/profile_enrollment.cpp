// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_enrollment.h"

#include "ayu/data/ayu_database.h"
#include "ayu/features/emergency_actions/scoped_account_clear.h"
#include "ayu/features/profile_sets/profile_account_storage.h"
#include "ayu/features/profile_sets/profile_emergency_settings.h"
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
		UserId expectedUser,
		MTP::Environment expectedEnvironment) {
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
		} else if (identity->userId == expectedUser && identity->environment == expectedEnvironment) {
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

bool DiscardStagedAccount(
		const MigrationController &workspace,
		const QByteArray &vaultId,
		const AccountKey &key,
		const AccountVaultLocator &locator,
		UserId expectedUser) {
	const auto name = AccountVaultDataName(locator);
	const auto accounts = workspace.accountStorageRoot();
	const auto paths = Storage::ScopedAccountPaths(accounts, name);
	if (paths) {
		const auto directory = QFileInfo(QFileInfo(paths->authPath).path());
		if (!directory.exists() && !directory.isSymLink() && !directory.isJunction()) {
			return true;
		}
	}
	const auto localKey = ProfileAccountStorageKey(key);
	const auto identity = paths && localKey
		? Storage::ValidateScopedAccountForStartup(*paths, localKey) : std::nullopt;
	if (!identity || identity->userId != expectedUser) {
		return false;
	}
	const auto installation = EmergencyActions::InstallationId(vaultId.toHex().toStdString());
	const auto account = EmergencyActions::AccountId(name.toStdString());
	auto clear = EmergencyActions::ScopedAccountClear(installation,
		QFileInfo(QFileInfo(workspace.workspacePath()).path()).filesystemFilePath(), {
			.installationId = installation,
			.accountStorageRoot = QFileInfo(accounts).filesystemFilePath(),
			.accounts = {{ account, name.toStdString() }},
		});
	return clear.clear(account) == EmergencyActions::EffectResult::ConfirmedSuccess;
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
	const auto checked = CheckExistingIdentities(root, *master, request.userId, request.environment);
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
	const auto discard = [&] {
		return workspace.WithCurrentGeneration(committed->transactionId, [&] {
			return DiscardStagedAccount(workspace, vault->id, *key, *locator, request.userId);
		});
	};
	auto migrationError = MigrationError::None;
	if (!workspace.WithCurrentGeneration(committed->transactionId, operation, &migrationError)) {
		const auto cleaned = migrationError != MigrationError::CallbackFailed || discard();
		return (migrationError == MigrationError::StaleGeneration || !cleaned)
			? Result::Stale : Result::StorageFailed;
	}
	const auto next = MigrationController::NewTransactionId();
	const auto rules = next.isEmpty() ? std::nullopt : RebindProfileEmergencyRulesOnWorker(
		workspace, *committed, *enrolled, next, admin);
	if (!rules) {
		return discard() && !committed->emergencyRules.isEmpty()
			? Result::RuleUpdateRequired : Result::StorageFailed;
	}
	auto artifacts = std::vector<MigrationInput>{
		{ MigrationArtifact::ProfileVault, sealed }, { MigrationArtifact::AccountKeyring, keyring },
	};
	if (!rules->isEmpty()) {
		artifacts.push_back({ MigrationArtifact::EmergencyRules, *rules });
	}
	const auto published = workspace.ReplaceCommitted(committed->transactionId, artifacts,
		[&](const CommittedMigration &record) {
		return record.profileVault == sealed && record.accountKeyring == keyring
			&& record.emergencyRules == *rules && record.emergencyRecovery.isEmpty();
	}, &migrationError, next);
	if (published) {
		return workspace.RetireInactiveGenerations(published->transactionId)
			? Result::Complete : Result::Stale;
	}
	if (migrationError == MigrationError::StaleGeneration
		|| migrationError == MigrationError::PublicationUncertain || !discard()) {
		return Result::Stale;
	}
	return Result::StorageFailed;
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
