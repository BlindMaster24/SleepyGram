// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_setup.h"

#include "ayu/ayu_preferences_migration.h"
#include "ayu/features/profile_sets/profile_generation.h"
#include "ayu/features/profile_sets/profile_staging.h"
#include "ayu/features/profile_sets/profile_migration.h"
#include "crl/crl_async.h"
#include "crl/crl_on_main.h"
#include "mtproto/mtproto_auth_key.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/storage_domain.h"
#include "wallet/wallet_vault.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QDirIterator>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QtEndian>
#include <openssl/crypto.h>

#include <algorithm>
#include <map>
#include <set>

namespace Ayu::ProfileSets {
namespace {

using Result = ProfileSetupResult;
constexpr auto kDigestSize = 32;

void Wipe(QByteArray &value) {
	OPENSSL_cleanse(value.data(), size_t(value.size()));
	value.clear();
}

void Wipe(DerivedCredential &value) {
	Wipe(value.key);
	Wipe(value.verifier);
}

void Wipe(std::vector<AccountKey> &keys) {
	for (auto &item : keys) {
		Wipe(item.key);
	}
}

struct ObservedAccount final {
	int index = 0;
	UserId userId;
};

struct OpenSetupPlan final {
	std::vector<ProfileStagingAccount> accounts;
	SetId initialSet;
	MTP::AuthKeyPtr settingsKey;
};

DerivedCredential Derive(
		const QByteArray &salt,
		KdfParameters kdf,
		const QString &text) {
	auto passcode = text.toUtf8();
	const auto wipe = gsl::finally([&] { Wipe(passcode); });
	const auto key = Storage::details::CreatePasscodeKey(passcode, salt, {
		.kind = kdf.kind,
		.memory = kdf.memory,
		.time = kdf.time,
		.parallel = kdf.parallel,
	});
	if (!key) {
		return {};
	}
	const auto bytes = key->data();
	return details::ProfileVaultCredentialFromKdfOutput(QByteArrayView(
		reinterpret_cast<const char*>(bytes.data()), qsizetype(bytes.size())));
}

bool UnsupportedLegacyData(const QString &root) {
	const auto rotatedArchive = QDir(root).entryList(
		{ u"ayudata_*.db"_q, u"ayudata_*.db-wal"_q, u"ayudata_*.db-shm"_q },
		QDir::AllEntries | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot);
	return !rotatedArchive.isEmpty();
}

bool LegacyWalletRingPresent(const LegacyRetirementPlan &plan) {
	const auto stem = plan.dataDirectory + u"/wallet_keyring_"_q + plan.dataName;
	for (const auto suffix : { 's', '0', '1' }) {
		const auto info = QFileInfo(stem + suffix);
		if (info.exists() || info.isSymLink() || info.isJunction()) {
			return true;
		}
	}
	return false;
}

QByteArray DirectoryDigest(const QString &root) {
	if (root.isEmpty() || QFileInfo(root).canonicalFilePath() != root) {
		return {};
	}
	auto names = QStringList();
	auto iterator = QDirIterator(root,
		QDir::AllEntries | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
		QDirIterator::Subdirectories);
	while (iterator.hasNext()) {
		names.push_back(iterator.next());
	}
	std::ranges::sort(names);
	auto digest = QCryptographicHash(QCryptographicHash::Sha256);
	for (const auto &path : names) {
		const auto info = QFileInfo(path);
		if (info.isSymLink() || info.isJunction() || info.canonicalFilePath() != path
			|| (!info.isDir() && !info.isFile())) {
			return {};
		}
		const auto name = path.sliced(root.size() + 1).toUtf8();
		const auto nameSize = qToBigEndian(quint64(name.size()));
		const auto size = qToBigEndian(info.isDir() ? quint64(-1) : quint64(info.size()));
		digest.addData(QByteArrayView(reinterpret_cast<const char*>(&nameSize), sizeof(nameSize)));
		digest.addData(name);
		digest.addData(QByteArrayView(reinterpret_cast<const char*>(&size), sizeof(size)));
		if (info.isFile()) {
			auto file = QFile(path);
			if (!file.open(QIODevice::ReadOnly) || !digest.addData(&file)
				|| file.size() != info.size()) {
				return {};
			}
		}
	}
	return digest.result();
}

QByteArray ScopedDataDigest(const MigrationController &workspace) {
	const auto accounts = DirectoryDigest(workspace.accountStorageRoot());
	const auto settings = QDir(workspace.workspacePath()).filePath(u"set-settings"_q);
	const auto info = QFileInfo(settings);
	if (accounts.isEmpty() || info.isSymLink() || info.isJunction()) {
		return {};
	} else if (!info.exists()) {
		return accounts;
	}
	const auto settingsDigest = DirectoryDigest(settings);
	return settingsDigest.isEmpty() ? QByteArray() : QCryptographicHash::hash(
		accounts + settingsDigest, QCryptographicHash::Sha256);
}

std::optional<std::vector<ObservedAccount>> ObserveLegacyAccounts(
		const ProfileSetupRequest &request,
		const Storage::LegacyProfileInventory &inventory) {
	auto observed = std::vector<ObservedAccount>();
	auto usedIds = std::set<UserId>();
	for (const auto index : inventory.accountIndices) {
		const auto paths = Storage::AccountPathsForDataName(
			request.dataDirectory, Storage::AccountDataName(request.dataName, index));
		const auto user = Storage::ReadLegacyAccountUserForMigration(
			paths, inventory.localKey);
		if (!user || !usedIds.insert(user).second) {
			return std::nullopt;
		}
		observed.push_back({ .index = index, .userId = user });
	}
	return observed;
}

std::optional<CommittedMigration> CreateDraft(
		const ProfileSetupRequest &request,
		const std::vector<ObservedAccount> &observed) {
	const auto salt = NewVerifierSalt();
	const auto initial = Storage::details::DefaultPasscodeKdf();
	const auto kdf = KdfParameters{
		.kind = initial.kind,
		.memory = initial.memory,
		.time = initial.time,
		.parallel = initial.parallel,
	};
	if (!details::ValidProfileVaultSalt(salt) || !ValidProfileVaultKdf(kdf)) {
		return std::nullopt;
	}
	auto admin = Derive(salt, kdf, request.masterPasscode);
	auto set = Derive(salt, kdf, request.firstSetPasscode);
	const auto wipeCredentials = gsl::finally([&] { Wipe(admin); Wipe(set); });
	if (!admin.valid() || !set.valid() || admin.verifier == set.verifier) {
		return std::nullopt;
	}
	auto metadata = Metadata{
		.verifierSalt = salt,
		.verifierKdf = kdf,
		.masterVerifier = admin.verifier,
		.sets = { AccountSet{
			.id = NewSetId(),
			.name = request.firstSetName,
			.verifier = set.verifier,
		} },
	};
	auto keys = std::vector<AccountKey>();
	const auto wipeKeys = gsl::finally([&] { Wipe(keys); });
	auto locators = std::vector<AccountVaultLocator>();
	for (const auto &account : observed) {
		const auto id = NewAccountId();
		auto key = NewAccountKey(id);
		auto locator = NewAccountVaultLocator(id);
		if (!key || !locator || !account.userId) {
			if (key) {
				Wipe(key->key);
			}
			return std::nullopt;
		}
		keys.push_back(std::move(*key));
		locators.push_back(std::move(*locator));
		metadata.sets.front().accounts.push_back(id);
	}
	auto grants = std::vector<SetGrantCredential>{ { metadata.sets.front().id, set } };
	const auto wipeGrants = gsl::finally([&] { Wipe(grants.front().credential); });
	const auto vault = SealProfileVault(metadata, keys, locators, admin, grants);
	if (!vault) {
		return std::nullopt;
	}
	auto result = CommittedMigration{
		.transactionId = MigrationController::NewTransactionId(),
		.profileVault = SerializeProfileVault(*vault),
		.accountKeyring = SealAccountKeyring(keys, admin.key),
	};
	return (!result.transactionId.isEmpty() && !result.profileVault.isEmpty()
		&& !result.accountKeyring.isEmpty()) ? std::optional(std::move(result)) : std::nullopt;
}

std::optional<OpenSetupPlan> OpenDraftPlan(
		const CommittedMigration &draft,
		const ProfileSetupRequest &request,
		const std::vector<ObservedAccount> &observed) {
	const auto vault = ParseProfileVault(draft.profileVault);
	if (!vault || vault->version != kProfileVaultVersion) {
		return std::nullopt;
	}
	auto master = Derive(vault->salt, vault->kdf, request.masterPasscode);
	auto set = Derive(vault->salt, vault->kdf, request.firstSetPasscode);
	const auto wipeCredentials = gsl::finally([&] { Wipe(master); Wipe(set); });
	auto adminAccess = OpenProfileVault(*vault, master);
	auto setAccess = OpenProfileVault(*vault, set);
	const auto admin = std::get_if<AdminVaultAccess>(&adminAccess);
	const auto member = std::get_if<SetVaultAccess>(&setAccess);
	auto keyring = OpenAccountKeyring(draft.accountKeyring, master.key);
	const auto wipeAccess = gsl::finally([&] {
		if (admin) Wipe(admin->accounts);
		if (member) {
			Wipe(member->accounts);
			Wipe(member->settingsKey);
		}
		if (keyring) Wipe(*keyring);
	});
	if (!admin || !member || !keyring || *keyring != admin->accounts
		|| admin->accounts != member->accounts
		|| admin->locators != member->locators
		|| admin->metadata.sets.size() != 1) {
		return std::nullopt;
	}
	const auto &initial = admin->metadata.sets.front();
	if (initial.id != member->id || initial.name != request.firstSetName
		|| initial.accounts.size() != observed.size()
		|| admin->accounts.size() != observed.size()) {
		return std::nullopt;
	}
	auto settingsKey = ProfileSettingsStorageKey(member->settingsKey);
	if (!settingsKey) {
		return std::nullopt;
	}
	auto keys = std::map<AccountId, AccountKey*>();
	auto locators = std::map<AccountId, const AccountVaultLocator*>();
	for (auto &key : admin->accounts) keys.emplace(key.id, &key);
	for (const auto &locator : admin->locators) locators.emplace(locator.id, &locator);
	if (std::ranges::any_of(initial.accounts, [&](AccountId id) {
		return !keys.contains(id) || !locators.contains(id);
	})) {
		return std::nullopt;
	}
	auto result = std::vector<ProfileStagingAccount>();
	result.reserve(observed.size());
	for (auto i = size_t(0); i != observed.size(); ++i) {
		const auto id = initial.accounts[i];
		result.push_back({
			.slot = observed[i].index,
			.userId = observed[i].userId,
			.key = std::move(*keys.at(id)),
			.locator = *locators.at(id),
		});
	}
	return OpenSetupPlan{
		.accounts = std::move(result),
		.initialSet = initial.id,
		.settingsKey = std::move(settingsKey),
	};
}

Result Setup(ProfileSetupRequest &request) {
	if (request.masterPasscode == request.firstSetPasscode
		|| request.masterPasscode.isEmpty() || request.firstSetPasscode.isEmpty()
		|| request.masterPasscode.size() > 1024 || request.firstSetPasscode.size() > 1024
		|| request.legacyPasscode.size() > 1024 || request.firstSetName.isEmpty()) {
		return Result::InvalidInput;
	}
	const auto workspace = MigrationController::OpenProfileWorkspace(request.dataDirectory);
	if (!workspace || workspace->LoadCommitted()) {
		return Result::StorageFailed;
	}
	if (UnsupportedLegacyData(request.dataDirectory)) {
		return Result::UnsupportedLegacyData;
	}
	auto legacyPasscode = request.legacyPasscode.toUtf8();
	const auto wipeLegacyPasscode = gsl::finally([&] { Wipe(legacyPasscode); });
	const auto inventory = Storage::ReadLegacyProfileInventory(
		request.dataDirectory, request.dataName, legacyPasscode);
	if (!inventory) {
		return Result::LegacyPasscodeRejected;
	}
	const auto observed = ObserveLegacyAccounts(request, *inventory);
	if (!observed) {
		return Result::UnsupportedLegacyData;
	}
	auto users = std::vector<quint64>();
	users.reserve(observed->size());
	for (const auto &account : *observed) {
		users.push_back(account.userId.bare);
	}
	const auto preferences = Preferences::ReadLegacyPartition(request.dataDirectory, users);
	if (!preferences) {
		return Result::UnsupportedLegacyData;
	}
	auto draft = workspace->LoadSetupDraft();
	if (!draft) {
		draft = CreateDraft(request, *observed);
		if (!draft || !workspace->StoreSetupDraft(*draft)) {
			return Result::StorageFailed;
		}
	}
	auto setup = OpenDraftPlan(*draft, request, *observed);
	if (!setup) {
		return Result::SetupPasscodeRejected;
	}
	const auto wipeAccounts = gsl::finally([&] {
		for (auto &account : setup->accounts) Wipe(account.key.key);
	});
	const auto settings = workspace->PrepareInitialSettingsDirectory(
		draft->transactionId, setup->initialSet);
	if (!settings || !Preferences::StageScopedGlobalPreferences(
			*settings, setup->settingsKey, preferences->globals)) {
		return Result::VerificationFailed;
	}
	auto retirement = LegacyRetirementPlan();
	auto distinctWalletPasscode = request.legacyWalletPasscode.toUtf8();
	const auto wipeWalletPasscode = gsl::finally([&] { Wipe(distinctWalletPasscode); });
	const auto walletPasscode = Wallet::SecureBytes(distinctWalletPasscode.isEmpty()
		? legacyPasscode
		: distinctWalletPasscode);
	const auto staged = StageScopedProfileData(
		*workspace, request.dataDirectory, request.dataName, legacyPasscode,
		setup->accounts, draft->transactionId, &retirement, &*preferences,
		request.preserveLegacyWebviewStorage
			? Storage::LegacyWebviewTransfer::StartFresh
			: Storage::LegacyWebviewTransfer::RequireIsolated,
		walletPasscode.empty() ? nullptr : &walletPasscode);
	if (staged == ProfileStagingResult::LegacyWalletPasscodeRequired) {
		return Result::LegacyWalletPasscodeRequired;
	} else if (staged == ProfileStagingResult::LegacyWalletPasscodeRejected) {
		return Result::LegacyWalletPasscodeRejected;
	} else if (staged != ProfileStagingResult::Success) {
		return (staged == ProfileStagingResult::UnsupportedAccountData)
			? Result::UnsupportedLegacyData
			: Result::VerificationFailed;
	}
	const auto dataDigest = ScopedDataDigest(*workspace);
	const auto serialized = SerializeLegacyRetirementPlan(retirement);
	if (dataDigest.size() != kDigestSize || serialized.isEmpty()) {
		return Result::VerificationFailed;
	}
	auto receipt = dataDigest + serialized;
	const auto existing = workspace->LoadStaged();
	if (existing && existing->legacyRetirement != receipt) {
		retirement.walletInventoryVerified = false;
		const auto oldFormat = SerializeLegacyRetirementPlan(retirement);
		if (oldFormat.isEmpty() || LegacyWalletRingPresent(retirement)
			|| existing->legacyRetirement != dataDigest + oldFormat) {
			return Result::VerificationFailed;
		}
		receipt = existing->legacyRetirement;
	}
	if (!existing && !workspace->Stage({
			{ MigrationArtifact::ProfileVault, draft->profileVault },
			{ MigrationArtifact::AccountKeyring, draft->accountKeyring },
			{ MigrationArtifact::LegacyRetirement, receipt },
		}, nullptr, draft->transactionId)) {
		return Result::StorageFailed;
	}
	const auto committed = workspace->CommitVerified([&](const CommittedMigration &record) {
		return record.transactionId == draft->transactionId
			&& record.profileVault == draft->profileVault
			&& record.accountKeyring == draft->accountKeyring
			&& record.legacyRetirement == receipt && record.emergencyRules.isEmpty();
	});
	if (!committed) {
		return Result::VerificationFailed;
	} else if (!FinishProfileRetirement(request.dataDirectory)) {
		return Result::RetirementPending;
	} else if (request.layout != ProfileSetupLayout::RevocableGates) {
		return Result::Complete;
	}
	const auto current = workspace->LoadCommitted();
	if (!current || current->layout != MigrationGenerationLayout::LegacyKeys
		|| current->profileVault != committed->profileVault
		|| current->accountKeyring != committed->accountKeyring
		|| !current->legacyRetirement.isEmpty()) {
		return Result::RetirementPending;
	}
	const auto vault = ParseProfileVault(current->profileVault);
	if (!vault) {
		return Result::RevocablePromotionDeferred;
	}
	auto admin = Derive(vault->salt, vault->kdf, request.masterPasscode);
	auto first = Derive(vault->salt, vault->kdf, request.firstSetPasscode);
	const auto wipeCredentials = gsl::finally([&] { Wipe(admin); Wipe(first); });
	const auto promoted = PromoteFreshRevocableProfileSetup(
		*workspace, current->proof(), std::move(admin), std::move(first),
		[&](const CommittedRevocableProfileGeneration &) {
			return ScopedDataDigest(*workspace) == dataDigest;
		});
	if (!promoted) {
		const auto active = workspace->LoadCommitted();
		return (active && active->proof() == current->proof())
			? Result::RevocablePromotionDeferred
			: Result::RetirementPending;
	}
	return workspace->RetireRevocableGenerations(*promoted)
		? Result::Complete
		: Result::RetirementPending;
}

} // namespace

void SetupProfileFromLegacy(ProfileSetupRequest request, Fn<void(ProfileSetupResult)> done) {
	crl::async([request = std::move(request), done = std::move(done)]() mutable {
		const auto result = Setup(request);
		request.legacyPasscode.fill(QChar(0));
		request.legacyWalletPasscode.fill(QChar(0));
		request.masterPasscode.fill(QChar(0));
		request.firstSetPasscode.fill(QChar(0));
		crl::on_main([done = std::move(done), result]() mutable { done(result); });
	});
}

bool FinishProfileRetirement(const QString &dataDirectory) {
	const auto workspace = MigrationController::OpenProfileWorkspace(dataDirectory);
	const auto committed = workspace ? workspace->LoadCommitted() : std::nullopt;
	if (!committed) {
		return false;
	} else if (committed->layout == MigrationGenerationLayout::RevocableGates) {
		return committed->revocableEmergencyRecovery.isEmpty()
			&& workspace->RetireRevocableGenerations(committed->proof());
	} else if (committed->legacyRetirement.isEmpty()) {
		return committed->emergencyRecovery.isEmpty()
			&& workspace->RetireInactiveGenerations(committed->transactionId);
	} else if (!committed->emergencyRules.isEmpty()) {
		return false;
	}
	if (committed->legacyRetirement.size() <= kDigestSize) {
		return false;
	}
	const auto plan = ParseLegacyRetirementPlan(committed->legacyRetirement.sliced(kDigestSize));
	if (!plan || !workspace->WithCurrentGeneration(committed->transactionId, [&] {
			return (plan->walletInventoryVerified || !LegacyWalletRingPresent(*plan))
				&& ScopedDataDigest(*workspace) == committed->legacyRetirement.first(kDigestSize)
				&& RetireLegacyProfileFiles(dataDirectory, committed->transactionId, *plan)
				== LegacyRetirementResult::Complete;
		})) {
		return false;
	}
	const auto scoped = workspace->ReplaceCommitted(committed->transactionId, {
		{ MigrationArtifact::ProfileVault, committed->profileVault },
		{ MigrationArtifact::AccountKeyring, committed->accountKeyring },
	}, [&](const CommittedMigration &verified) {
		return verified.profileVault == committed->profileVault
			&& verified.accountKeyring == committed->accountKeyring
			&& verified.legacyRetirement.isEmpty() && verified.emergencyRules.isEmpty();
	});
	return scoped && workspace->RetireInactiveGenerations(scoped->transactionId);
}

} // namespace Ayu::ProfileSets
