// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_generation.h"

#include "ayu/features/profile_sets/profile_revocable_emergency_bundle.h"
#include "base/openssl_help.h"
#include "storage/details/storage_hkdf.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QtEndian>

#include <openssl/crypto.h>

#include <algorithm>
#include <map>
#include <set>

namespace Ayu::ProfileSets {
namespace {

namespace EA = EmergencyActions;

bool ValidLandingId(QByteArrayView decoded) {
	return decoded.size() == 16 && std::ranges::any_of(decoded, [](char ch) { return ch != 0; });
}

SetId EnrollmentId(
		QByteArrayView context,
		QByteArrayView installationId,
		QByteArrayView operationTag) {
	if (!ValidLandingId(installationId) || !ValidLandingId(operationTag)) {
		return {};
	}
	auto digest = QCryptographicHash(QCryptographicHash::Sha256);
	digest.addData(context);
	digest.addData(installationId);
	digest.addData(operationTag);
	const auto bytes = digest.result();
	return { qFromBigEndian<quint64>(bytes.constData()), qFromBigEndian<quint64>(bytes.constData() + 8) };
}

std::span<const uint8_t> Uint8Bytes(QByteArrayView bytes) {
	return { reinterpret_cast<const uint8_t*>(bytes.data()), size_t(bytes.size()) };
}

void SetError(MigrationError *error, MigrationError value) {
	if (error) {
		*error = value;
	}
}

void SetError(ProfileGenerationError *error, ProfileGenerationError value) {
	if (error) {
		*error = value;
	}
}

void Cleanse(QByteArray &secret) {
	if (!secret.isEmpty()) {
		OPENSSL_cleanse(secret.data(), size_t(secret.size()));
	}
}

void Cleanse(DerivedCredential &credential) {
	Cleanse(credential.verifier);
	Cleanse(credential.key);
}

void Cleanse(std::vector<AccountKey> &keys) {
	for (auto &key : keys) {
		Cleanse(key.key);
	}
}

bool SameKey(const AccountKey &a, const AccountKey &b) {
	return a.id == b.id && a.key.size() == kAccountKeySize && b.key.size() == kAccountKeySize
		&& CRYPTO_memcmp(a.key.constData(), b.key.constData(), kAccountKeySize) == 0;
}

std::optional<CommittedRevocableProfileGeneration> ParseRevocableGeneration(
		const CommittedMigration &committed,
		MigrationError *error) {
	SetError(error, MigrationError::InvalidManifest);
	if (committed.layout != MigrationGenerationLayout::RevocableGates
		|| !committed.accountKeyring.isEmpty() || !committed.legacyRetirement.isEmpty()
		|| !committed.emergencyRules.isEmpty() || !committed.emergencyRecovery.isEmpty()
		|| committed.transactionId.size() != 16 || committed.manifestDigest.size() != 32) {
		return std::nullopt;
	}
	auto vault = RevocableProfileVault::Parse(committed.profileVault);
	auto gates = ParseAccountGateTable(committed.accountGateTable, committed.installationId);
	if (!vault || !gates || vault->installationId() != committed.installationId) {
		return std::nullopt;
	}
	SetError(error, MigrationError::None);
	return CommittedRevocableProfileGeneration{
		.proof = committed.proof(),
		.vault = std::move(*vault),
		.gates = std::move(*gates),
		.retirementPending = committed.retirementPending,
	};
}

std::optional<CommittedMigration> ReadExpected(
		const MigrationController &sidecar,
		const MigrationGenerationProof &expected,
		MigrationError *error,
		bool forSetEdit = false) {
	auto current = sidecar.LoadCommitted(error);
	if (!current) {
		return std::nullopt;
	} else if (current->proof() != expected) {
		SetError(error, MigrationError::StaleGeneration);
		return std::nullopt;
	} else if (!current->revocableEmergencyRecovery.isEmpty()) {
		SetError(error, MigrationError::RevocableRecoveryRequired);
		return std::nullopt;
	} else if (current->retirementPending) {
		SetError(error, MigrationError::RevocableRetirementRequired);
		return std::nullopt;
	} else if (!current->emergencyRecovery.isEmpty()) {
		SetError(error, MigrationError::InvalidInput);
		return std::nullopt;
	} else if (!forSetEdit && !current->revocableEmergencyRules.isEmpty()) {
		SetError(error, MigrationError::VerificationRequired);
		return std::nullopt;
	}
	return current;
}

std::optional<MigrationGenerationProof> Publish(
		const MigrationController &sidecar,
		const CommittedMigration &current,
		const QByteArray &installationId,
		QByteArray vault,
		QByteArray gates,
		const VerifyRevocableProfileGeneration &verify,
		MigrationError *error,
		QByteArray transactionId,
		const QByteArray &preservedRules = {}) {
	auto inputs = std::vector<MigrationInput>{
		{ MigrationArtifact::ProfileVault, vault },
		{ MigrationArtifact::AccountGateTable, gates },
	};
	if (!preservedRules.isEmpty()) {
		inputs.push_back({ MigrationArtifact::RevocableEmergencyRules, preservedRules });
	}
	const auto published = sidecar.ReplaceRevocableCommitted(
		current.proof(),
		installationId,
		inputs,
		[&](const CommittedMigration &candidate) {
			const auto decoded = ParseRevocableGeneration(candidate, nullptr);
			return decoded
				&& candidate.installationId == installationId
				&& candidate.profileVault == vault
				&& candidate.accountGateTable == gates
				&& candidate.emergencyRules.isEmpty()
				&& candidate.emergencyRecovery.isEmpty()
				&& candidate.revocableEmergencyRules == preservedRules
				&& candidate.revocableEmergencyRecovery.isEmpty()
				&& (!verify || verify(*decoded));
		},
		error,
		std::move(transactionId));
	return published ? std::optional(published->proof()) : std::nullopt;
}

bool CatalogMatches(
		const AdminVaultAccess &legacy,
		const std::vector<AccountKey> &keyring,
		const RevocableAdminVaultAccess &current,
		const AccountGateTable &gates) {
	if (legacy.metadata != current.metadata
		|| legacy.accounts.size() != current.accounts.size()
		|| legacy.accounts.size() != keyring.size()
		|| legacy.accounts.size() != gates.size()
		|| legacy.accounts.size() != legacy.locators.size()) {
		return false;
	}
	auto legacyKeys = std::map<AccountId, const AccountKey*>();
	auto legacyLocators = std::map<AccountId, QByteArrayView>();
	for (const auto &key : legacy.accounts) {
		legacyKeys.emplace(key.id, &key);
	}
	for (const auto &locator : legacy.locators) {
		legacyLocators.emplace(locator.id, locator.value);
	}
	for (const auto &key : keyring) {
		const auto match = legacyKeys.find(key.id);
		if (match == end(legacyKeys) || !SameKey(key, *match->second)) {
			return false;
		}
	}
	for (const auto &account : current.accounts) {
		const auto &binding = account.handle.binding();
		const auto key = legacyKeys.find(binding.id);
		const auto locator = legacyLocators.find(binding.id);
		if (key == end(legacyKeys) || locator == end(legacyLocators)
			|| locator->second != binding.locator || !account.handle.matches(account.permit)) {
			return false;
		}
		auto opened = OpenAccountGate(gates, account.handle);
		const auto gateKey = std::get_if<AccountKey>(&opened);
		if (!gateKey) {
			return false;
		}
		const auto wipe = gsl::finally([&] { Cleanse(gateKey->key); });
		if (!SameKey(*gateKey, *key->second)) {
			return false;
		}
	}
	return true;
}

std::optional<std::set<AccountId>> LiveCatalog(
		const RevocableAdminVaultAccess &access,
		const AccountGateTable &gates) {
	auto live = std::set<AccountId>();
	for (const auto &account : access.accounts) {
		const auto status = InspectAccountGate(gates, account.handle);
		if (status == AccountGateStatus::Unavailable) {
			return std::nullopt;
		} else if (status == AccountGateStatus::Active) {
			live.insert(account.handle.binding().id);
		}
	}
	return live;
}

void RemoveInactiveMemberships(Metadata &metadata, const std::set<AccountId> &live) {
	for (auto &set : metadata.sets) {
		std::erase_if(set.accounts, [&](AccountId id) { return !live.contains(id); });
	}
}

bool LiveMemberships(const Metadata &metadata, const std::set<AccountId> &live) {
	return std::ranges::all_of(metadata.sets, [&](const AccountSet &set) {
		return std::ranges::all_of(set.accounts, [&](AccountId id) { return live.contains(id); });
	});
}

void KeepUnchangedMemberships(
		const Metadata &before,
		Metadata &after,
		const std::set<AccountId> &live) {
	for (auto &set : after.sets) {
		const auto old = std::ranges::find(before.sets, set.id, &AccountSet::id);
		if (old == end(before.sets) || old->accounts == set.accounts) {
			continue;
		}
		auto visible = old->accounts;
		std::erase_if(visible, [&](AccountId id) { return !live.contains(id); });
		auto selected = set.accounts;
		std::ranges::sort(visible);
		std::ranges::sort(selected);
		if (visible == selected) {
			set.accounts = old->accounts;
		}
	}
}

std::optional<MigrationGenerationProof> PublishSetEdit(
		const MigrationController &sidecar,
		const CommittedMigration &current,
		const RevocableProfileVault &vault,
		const Metadata &before,
		const Metadata &metadata,
		const DerivedCredential &admin,
		const std::vector<SetGrantCredential> &replacements,
		MigrationError *error,
		QByteArray transactionId = {}) {
	if (!CanKeepRevocableProfileEmergencyRules(
			current.installationId, current.revocableEmergencyRules, admin, before, metadata)) {
		SetError(error, MigrationError::VerificationRequired);
		return std::nullopt;
	}
	const auto next = vault.updated(admin, metadata, replacements);
	if (!next) {
		SetError(error, MigrationError::VerificationFailed);
		return std::nullopt;
	}
	return Publish(sidecar, current, current.installationId, next->serialize(),
		current.accountGateTable, [&](const CommittedRevocableProfileGeneration &candidate) {
			const auto verified = candidate.vault.openMaster(admin);
			return verified && verified->metadata == metadata;
		}, error, std::move(transactionId), current.revocableEmergencyRules);
}

ProfileGenerationError EditError(MigrationError error) {
	using Error = ProfileGenerationError;
	switch (error) {
	case MigrationError::StaleGeneration: return Error::StaleGeneration;
	case MigrationError::RevocableRetirementRequired: return Error::RevocableRetirementRequired;
	case MigrationError::RevocableRecoveryRequired: return Error::EmergencyRecoveryRequired;
	case MigrationError::PublicationUncertain: return Error::PublicationUncertain;
	case MigrationError::VerificationRequired:
	case MigrationError::VerificationFailed: return Error::SettingsRejected;
	default: return Error::InvalidSidecar;
	}
}

std::optional<AccountStoragePlan> ResolveScopedPlan(
		const QString &root,
		const RevocableSetVaultAccess &scope,
		const AccountGateTable &gates,
		ProfileGenerationError *error) {
	auto keys = std::vector<AccountKey>();
	const auto wipe = gsl::finally([&] { Cleanse(keys); });
	auto locators = std::vector<AccountVaultLocator>();
	keys.reserve(scope.handles().size());
	locators.reserve(scope.handles().size());
	for (const auto &handle : scope.handles()) {
		auto opened = OpenAccountGate(gates, handle);
		if (std::holds_alternative<AccountGateRevoked>(opened)) {
			continue;
		}
		auto key = std::get_if<AccountKey>(&opened);
		if (!key) {
			SetError(error, ProfileGenerationError::KeyMismatch);
			return std::nullopt;
		}
		locators.push_back({ .id = key->id, .value = handle.binding().locator });
		keys.push_back(std::move(*key));
	}
	auto plan = BuildScopedAccountStoragePlan(root, std::move(keys), locators);
	if (!plan) {
		SetError(error, ProfileGenerationError::InvalidPlan);
	}
	return plan;
}

} // namespace

std::optional<ProfileGenerationUnlockParameters> ReadCommittedProfileUnlockParameters(
		const CommittedMigration &committed,
		ProfileGenerationError *error) {
	if (!committed.emergencyRecovery.isEmpty() || !committed.revocableEmergencyRecovery.isEmpty()) {
		SetError(error, ProfileGenerationError::EmergencyRecoveryRequired);
		return std::nullopt;
	}
	if (committed.layout == MigrationGenerationLayout::RevocableGates) {
		if (committed.retirementPending) {
			SetError(error, ProfileGenerationError::RevocableRetirementRequired);
			return std::nullopt;
		}
		const auto vault = RevocableProfileVault::Parse(committed.profileVault);
		if (!vault || vault->installationId() != committed.installationId) {
			SetError(error, ProfileGenerationError::InvalidVault);
			return std::nullopt;
		}
		SetError(error, ProfileGenerationError::None);
		return ProfileGenerationUnlockParameters{ .salt = vault->salt(), .kdf = vault->kdf() };
	}
	const auto vault = ParseProfileVault(committed.profileVault);
	if (!vault || vault->version != kProfileVaultVersion) {
		SetError(error, ProfileGenerationError::InvalidVault);
		return std::nullopt;
	}
	SetError(error, ProfileGenerationError::None);
	return ProfileGenerationUnlockParameters{ .salt = vault->salt, .kdf = vault->kdf };
}

std::optional<CommittedRevocableProfileGeneration> LoadRevocableProfileGeneration(
		const MigrationController &sidecar,
		MigrationError *error) {
	const auto active = sidecar.LoadCommitted(error);
	return active ? ParseRevocableGeneration(*active, error) : std::nullopt;
}

bool WithCurrentRevocableProfileGeneration(
		const MigrationController &sidecar,
		const MigrationGenerationProof &expected,
		const VerifyRevocableProfileGeneration &useCurrent,
		MigrationError *error) {
	if (!useCurrent) {
		SetError(error, MigrationError::InvalidInput);
		return false;
	}
	auto failedParse = false;
	const auto result = sidecar.WithCurrentRevocableGeneration(
		expected,
		[&](const CommittedMigration &committed) {
			const auto active = ParseRevocableGeneration(committed, nullptr);
			failedParse = !active;
			return active && useCurrent(*active);
		},
		error);
	if (failedParse) {
		SetError(error, MigrationError::InvalidManifest);
	}
	return result;
}

std::optional<OpenedProfileGeneration> AuthenticateCommittedRevocableProfileGeneration(
		const MigrationController &sidecar,
		DerivedCredential credential,
		const MigrationGenerationProof &expected,
		ProfileGenerationError *error) {
	const auto wipe = gsl::finally([&] { Cleanse(credential); });
	SetError(error, ProfileGenerationError::InvalidSidecar);
	const auto root = sidecar.accountStorageRoot();
	if (root.isEmpty() || sidecar.isIsolatedFixture()) {
		return std::nullopt;
	}
	auto opened = std::optional<OpenedProfileGeneration>();
	auto migrationError = MigrationError::None;
	const auto authenticated = WithCurrentRevocableProfileGeneration(sidecar, expected,
		[&](const CommittedRevocableProfileGeneration &current) {
			auto vaultError = ProfileVaultError::None;
			auto access = current.vault.open(credential, &vaultError);
			if (std::holds_alternative<WrongPassword>(access)) {
				SetError(error, (vaultError == ProfileVaultError::WrongPassword
					|| vaultError == ProfileVaultError::AuthenticationFailed)
					? ProfileGenerationError::WrongPassword
					: ProfileGenerationError::InvalidVault);
				return false;
			}
			if (const auto admin = std::get_if<RevocableAdminVaultAccess>(&access)) {
				const auto live = LiveCatalog(*admin, current.gates);
				if (!live) {
					SetError(error, ProfileGenerationError::KeyMismatch);
					return false;
				}
				RemoveInactiveMemberships(admin->metadata, *live);
				opened.emplace(OpenedProfileGeneration(
					AccountStoragePlan(),
					{ .role = ProfileGenerationRole::Master },
					current.proof.transactionId,
					std::move(admin->metadata),
					{},
					std::vector<AccountId>(live->begin(), live->end()),
					current.proof,
					sidecar.workspacePath()));
				return true;
			}
			const auto &set = std::get<RevocableSetVaultAccess>(access);
			auto plan = ResolveScopedPlan(root, set, current.gates, error);
			if (!plan) {
				return false;
			}
			opened.emplace(OpenedProfileGeneration(
				std::move(*plan),
				{ .role = ProfileGenerationRole::Set, .setId = set.id() },
				current.proof.transactionId,
				std::nullopt,
				set.settingsKey().toByteArray(),
				{},
				current.proof,
				sidecar.workspacePath()));
			return true;
		}, &migrationError);
	if (authenticated) {
		SetError(error, ProfileGenerationError::None);
		return opened;
	}
	if (migrationError == MigrationError::StaleGeneration) {
		SetError(error, ProfileGenerationError::StaleGeneration);
	} else if (migrationError == MigrationError::RevocableRetirementRequired) {
		SetError(error, ProfileGenerationError::RevocableRetirementRequired);
	} else if (migrationError == MigrationError::RevocableRecoveryRequired) {
		SetError(error, ProfileGenerationError::EmergencyRecoveryRequired);
	}
	return std::nullopt;
}

SetId RevocableEnrollmentSetId(QByteArrayView installationId, QByteArrayView operationTag) {
	return EnrollmentId("SleepyGram revocable enrollment set v3", installationId, operationTag);
}

std::optional<OpenedProfileGeneration> OpenRevocableEmergencyEnrollment(
		const MigrationController &sidecar,
		const MigrationGenerationProof &expected,
		QByteArrayView operationTag,
		DerivedCredential credential,
		ProfileGenerationError *error) {
	const auto wipe = gsl::finally([&] { Cleanse(credential); });
	SetError(error, ProfileGenerationError::InvalidSidecar);
	if (sidecar.isIsolatedFixture() || sidecar.accountStorageRoot().isEmpty()
		|| !ValidLandingId(operationTag)
		|| !details::ValidRevocableProfileCredential(credential)) {
		return std::nullopt;
	}
	auto opened = std::optional<OpenedProfileGeneration>();
	auto migrationError = MigrationError::None;
	const auto authorized = sidecar.WithCurrentRevocableGeneration(expected, [&](const auto &committed) {
		const auto bundle = ParseRevocableProfileEmergencyBundle(
			committed.installationId, committed.revocableEmergencyRules);
		if (!bundle || !ParseRevocableGeneration(committed, nullptr)) {
			return false;
		}
		const auto authenticated = EA::AuthenticateEmergencyRule(
			bundle->rules.authority, Uint8Bytes(bundle->rules.rules), Uint8Bytes(credential.key));
		const auto ticket = std::get_if<EA::EmergencyRuleTicket>(&authenticated);
		if (!ticket || !ticket->details().executionCapsuleDigest
			|| ticket->details().rule.action == EA::EmergencyAction::RemoveInstallation) {
			SetError(error, ProfileGenerationError::WrongPassword);
			return false;
		}
		const auto &digest = *ticket->details().executionCapsuleDigest;
		const auto capsule = QByteArray(reinterpret_cast<const char*>(digest.data()), digest.size());
		const auto landing = bundle->landings.find(capsule);
		if (landing == end(bundle->landings) || !bundle->consumed.contains(capsule)
			|| landing->second != operationTag
			|| landing->second != RevocableEnrollmentOperation(ticket->details().operationId)) {
			SetError(error, ProfileGenerationError::WrongPassword);
			return false;
		}
		const auto future = RevocableEnrollmentSetId(committed.installationId, operationTag);
		const auto transient = EnrollmentId(
			"SleepyGram revocable enrollment settings scope v3",
			committed.installationId, operationTag);
		if (!future || !transient || future == transient) {
			return false;
		}
		auto settings = QByteArray(kProfileVaultKeySize, Qt::Uninitialized);
		const auto wipeSettings = gsl::finally([&] { Cleanse(settings); });
		const auto context = QByteArray("SleepyGram revocable enrollment temporary settings key v3")
			+ committed.installationId + operationTag.toByteArray();
		if (!Storage::HkdfSha256(bytes::make_span(credential.key.constData(), credential.key.size()),
				{}, bytes::make_span(context.constData(), context.size()),
				bytes::make_span(settings.data(), settings.size()))) {
			SetError(error, ProfileGenerationError::DerivationFailed);
			return false;
		}
		opened.emplace(OpenedProfileGeneration(
			AccountStoragePlan(),
			{
				.role = ProfileGenerationRole::Set,
				.setId = transient,
				.enrollment = RevocableEnrollmentLanding{ future, operationTag.toByteArray() },
			},
			expected.transactionId,
			std::nullopt,
			std::move(settings),
			{},
			expected,
			sidecar.workspacePath()));
		return true;
	}, &migrationError);
	if (!authorized) {
		if (migrationError != MigrationError::CallbackFailed) {
			SetError(error, EditError(migrationError));
		}
		return std::nullopt;
	}
	SetError(error, ProfileGenerationError::None);
	return opened;
}

std::optional<MigrationGenerationProof> PromoteCommittedRevocableProfileGeneration(
		const MigrationController &sidecar,
		const MigrationGenerationProof &expected,
		const RevocableProfileVault &vault,
		const AccountGateTable &gates,
		DerivedCredential admin,
		const VerifyRevocableProfileGeneration &verify,
		MigrationError *error,
		QByteArray transactionId) {
	const auto wipeAdmin = gsl::finally([&] { Cleanse(admin); });
	if (!verify) {
		SetError(error, MigrationError::VerificationRequired);
		return std::nullopt;
	}
	const auto current = ReadExpected(sidecar, expected, error);
	if (!current) {
		return std::nullopt;
	}
	SetError(error, MigrationError::VerificationFailed);
	if (current->layout != MigrationGenerationLayout::LegacyKeys
		|| !current->legacyRetirement.isEmpty() || !current->emergencyRules.isEmpty()) {
		return std::nullopt;
	}
	const auto legacy = ParseProfileVault(current->profileVault);
	if (!legacy || legacy->version != kProfileVaultVersion
		|| legacy->id != vault.installationId()
		|| legacy->id != gates.installationId()) {
		return std::nullopt;
	}
	auto legacyAccess = OpenProfileVault(*legacy, admin);
	const auto legacyMaster = std::get_if<AdminVaultAccess>(&legacyAccess);
	if (!legacyMaster) {
		return std::nullopt;
	}
	const auto wipeLegacy = gsl::finally([&] { Cleanse(legacyMaster->accounts); });
	auto keyring = OpenAccountKeyring(current->accountKeyring, admin.key);
	if (!keyring) {
		return std::nullopt;
	}
	const auto wipeKeyring = gsl::finally([&] { Cleanse(*keyring); });
	const auto newAccess = vault.open(admin);
	const auto newMaster = std::get_if<RevocableAdminVaultAccess>(&newAccess);
	if (!newMaster || !CatalogMatches(*legacyMaster, *keyring, *newMaster, gates)) {
		return std::nullopt;
	}
	return Publish(sidecar, *current, vault.installationId(), vault.serialize(),
		SerializeAccountGateTable(gates), verify, error, std::move(transactionId));
}

std::optional<MigrationGenerationProof> PromoteFreshRevocableProfileSetup(
		const MigrationController &sidecar,
		const MigrationGenerationProof &expected,
		DerivedCredential admin,
		DerivedCredential firstSet,
		const VerifyRevocableProfileGeneration &verify,
		MigrationError *error) {
	const auto wipeCredentials = gsl::finally([&] {
		Cleanse(admin);
		Cleanse(firstSet);
	});
	if (!verify || sidecar.isIsolatedFixture()) {
		SetError(error, MigrationError::VerificationRequired);
		return std::nullopt;
	}
	const auto current = ReadExpected(sidecar, expected, error);
	if (!current) {
		return std::nullopt;
	}
	SetError(error, MigrationError::VerificationFailed);
	if (current->layout != MigrationGenerationLayout::LegacyKeys
		|| !current->legacyRetirement.isEmpty() || !current->emergencyRules.isEmpty()) {
		return std::nullopt;
	}
	const auto legacy = ParseProfileVault(current->profileVault);
	if (!legacy || legacy->version != kProfileVaultVersion) {
		return std::nullopt;
	}
	auto adminAccess = OpenProfileVault(*legacy, admin);
	auto setAccess = OpenProfileVault(*legacy, firstSet);
	const auto master = std::get_if<AdminVaultAccess>(&adminAccess);
	const auto set = std::get_if<SetVaultAccess>(&setAccess);
	const auto wipeAccess = gsl::finally([&] {
		if (master) {
			Cleanse(master->accounts);
		}
		if (set) {
			Cleanse(set->accounts);
			Cleanse(set->settingsKey);
		}
	});
	if (!master || !set || master->metadata.sets.size() != 1
		|| master->metadata.sets.front().id != set->id
		|| master->metadata.sets.front().accounts.size() != master->accounts.size()
		|| master->accounts != set->accounts || master->locators != set->locators
		|| set->settingsKey.size() != kProfileVaultKeySize) {
		return std::nullopt;
	}
	auto locators = std::map<AccountId, QByteArrayView>();
	for (const auto &locator : master->locators) {
		locators.emplace(locator.id, locator.value);
	}
	auto gates = AccountGateTable::Create(legacy->id);
	if (!gates) {
		return std::nullopt;
	}
	auto accounts = std::vector<RevocableAccountGrant>();
	accounts.reserve(master->accounts.size());
	for (const auto &key : master->accounts) {
		const auto locator = locators.find(key.id);
		auto added = (locator != end(locators))
			? CreateAccountGate(*gates, key, locator->second) : std::nullopt;
		if (!added) {
			return std::nullopt;
		}
		*gates = std::move(added->table);
		accounts.push_back({ std::move(added->handle), std::move(added->permit) });
	}
	auto initialGrant = std::vector<SetGrantCredential>{ { set->id, firstSet } };
	const auto wipeGrant = gsl::finally([&] { Cleanse(initialGrant.front().credential); });
	const auto v3 = RevocableProfileVault::Seal(
		legacy->id, master->metadata, accounts, admin, initialGrant);
	const auto transaction = MigrationController::NewTransactionId();
	if (!v3 || transaction.isEmpty()) {
		return std::nullopt;
	}
	auto publicationError = MigrationError::None;
	const auto published = PromoteCommittedRevocableProfileGeneration(
		sidecar, expected, *v3, *gates, admin,
		[&](const CommittedRevocableProfileGeneration &candidate) {
			const auto access = candidate.vault.open(firstSet);
			const auto scope = std::get_if<RevocableSetVaultAccess>(&access);
			return scope && scope->id() == set->id && scope->settingsKey() == set->settingsKey
				&& scope->handles().size() == accounts.size()
				&& std::ranges::all_of(scope->handles(), [&](const AccountGateHandle &handle) {
					return InspectAccountGate(candidate.gates, handle) == AccountGateStatus::Active;
				})
				&& verify(candidate);
		}, &publicationError, transaction);
	if (!published && publicationError == MigrationError::PublicationUncertain) {
		const auto active = sidecar.LoadCommitted();
		if (active && active->transactionId == transaction
			&& active->layout == MigrationGenerationLayout::RevocableGates
			&& active->installationId == legacy->id && active->profileVault == v3->serialize()
			&& active->accountGateTable == SerializeAccountGateTable(*gates)) {
			SetError(error, MigrationError::None);
			return active->proof();
		}
	}
	SetError(error, publicationError);
	return published;
}

std::optional<MigrationGenerationProof> UpdateCommittedRevocableProfileSets(
		const MigrationController &sidecar,
		const MigrationGenerationProof &expected,
		const Metadata &metadata,
		DerivedCredential admin,
		std::vector<SetGrantCredential> replacements,
		MigrationError *error,
		QByteArray transactionId) {
	const auto wipe = gsl::finally([&] {
		Cleanse(admin);
		for (auto &replacement : replacements) {
			Cleanse(replacement.credential);
		}
	});
	const auto current = ReadExpected(sidecar, expected, error, true);
	if (!current) {
		return std::nullopt;
	}
	const auto typed = ParseRevocableGeneration(*current, error);
	if (!typed) {
		return std::nullopt;
	}
	const auto master = typed->vault.openMaster(admin);
	const auto live = master ? LiveCatalog(*master, typed->gates) : std::nullopt;
	if (!live || !LiveMemberships(metadata, *live)) {
		SetError(error, MigrationError::VerificationFailed);
		return std::nullopt;
	}
	auto normalized = metadata;
	if (!current->revocableEmergencyRules.isEmpty()) {
		KeepUnchangedMemberships(master->metadata, normalized, *live);
	}
	return PublishSetEdit(sidecar, *current, typed->vault, master->metadata, normalized, admin, replacements,
		error, std::move(transactionId));
}

ProfileGenerationError CommitRevocableProfileSetChange(
		const MigrationController &sidecar,
		const MigrationGenerationProof &expected,
		const ProfileSetChange &change,
		DerivedCredential admin,
		std::optional<DerivedCredential> replacement) {
	using Error = ProfileGenerationError;
	auto replacements = std::vector<SetGrantCredential>();
	const auto wipe = gsl::finally([&] {
		Cleanse(admin);
		if (replacement) {
			Cleanse(*replacement);
		}
		for (auto &entry : replacements) {
			Cleanse(entry.credential);
		}
	});
	auto migrationError = MigrationError::None;
	const auto current = !sidecar.isIsolatedFixture()
		? ReadExpected(sidecar, expected, &migrationError, true)
		: std::nullopt;
	if (!current) {
		return EditError(migrationError);
	}
	const auto typed = ParseRevocableGeneration(*current, &migrationError);
	if (!typed) {
		return Error::InvalidVault;
	}
	auto vaultError = ProfileVaultError::None;
	auto master = typed->vault.openMaster(admin, &vaultError);
	if (!master) {
		return (vaultError == ProfileVaultError::WrongPassword
			|| vaultError == ProfileVaultError::InvalidCredential)
			? Error::WrongPassword
			: Error::InvalidVault;
	}
	const auto live = LiveCatalog(*master, typed->gates);
	if (!live) {
		return Error::KeyMismatch;
	} else if (!std::ranges::all_of(change.accounts, [&](AccountId id) {
		return live->contains(id);
	})) {
		return Error::SettingsRejected;
	}
	auto metadata = master->metadata;
	if (current->revocableEmergencyRules.isEmpty()) {
		RemoveInactiveMemberships(metadata, *live);
	}
	const auto changed = details::ApplyProfileSetChange(
		metadata, change, replacement, replacements);
	if (changed != Error::None) {
		return changed;
	}
	if (!current->revocableEmergencyRules.isEmpty()) {
		KeepUnchangedMemberships(master->metadata, metadata, *live);
	}
	const auto published = PublishSetEdit(
		sidecar, *current, typed->vault, master->metadata, metadata, admin, replacements, &migrationError);
	if (!published) {
		return EditError(migrationError);
	}
	return sidecar.RetireRevocableGenerations(*published)
		? Error::None
		: Error::PublicationUncertain;
}

std::optional<MigrationGenerationProof> RevokeCommittedRevocableAccounts(
		const MigrationController &sidecar,
		const MigrationGenerationProof &expected,
		std::span<const AccountGateRevocationPermit> permits,
		MigrationError *error,
		QByteArray transactionId) {
	const auto current = ReadExpected(sidecar, expected, error);
	if (!current) {
		return std::nullopt;
	}
	const auto typed = ParseRevocableGeneration(*current, error);
	if (!typed) {
		return std::nullopt;
	}
	const auto updated = RevokeAccountGates(typed->gates, permits);
	if (!updated) {
		SetError(error, MigrationError::VerificationFailed);
		return std::nullopt;
	}
	auto serialized = SerializeAccountGateTable(*updated);
	if (serialized == current->accountGateTable) {
		return sidecar.WithCurrentRevocableGeneration(expected, [](const auto&) { return true; }, error)
			? std::optional(expected)
			: std::nullopt;
	}
	return Publish(sidecar, *current, current->installationId, current->profileVault,
		std::move(serialized), {}, error, std::move(transactionId));
}

} // namespace Ayu::ProfileSets
