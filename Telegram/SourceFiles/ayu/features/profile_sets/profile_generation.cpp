/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_generation.h"

#include "base/assertion.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <map>
#include <set>
#include <type_traits>
#include <utility>

namespace Ayu::ProfileSets {
namespace {

void SetError(ProfileGenerationError *error, ProfileGenerationError value) {
	if (error) {
		*error = value;
	}
}

void CleanseKeys(std::vector<AccountKey> &keys) {
	for (auto &key : keys) {
		if (!key.key.isEmpty()) {
			OPENSSL_cleanse(key.key.data(), size_t(key.key.size()));
		}
	}
}

bool EqualKey(const QByteArray &a, const QByteArray &b) {
	return (a.size() == b.size())
		&& !CRYPTO_memcmp(a.constData(), b.constData(), size_t(a.size()));
}

void CleanseCredential(DerivedCredential &credential) {
	if (!credential.verifier.isEmpty()) {
		OPENSSL_cleanse(
			credential.verifier.data(),
			size_t(credential.verifier.size()));
	}
	if (!credential.key.isEmpty()) {
		OPENSSL_cleanse(credential.key.data(), size_t(credential.key.size()));
	}
}

struct CredentialWiper final {
	DerivedCredential &credential;
	~CredentialWiper() {
		CleanseCredential(credential);
	}
};

struct WrappingKeyWiper final {
	QByteArray &key;
	~WrappingKeyWiper() {
		if (!key.isEmpty()) {
			OPENSSL_cleanse(key.data(), size_t(key.size()));
		}
	}
};

struct KeysWiper final {
	std::vector<AccountKey> &keys;
	~KeysWiper() {
		CleanseKeys(keys);
	}
};

struct AccessWiper final {
	ProfileVaultAccess &access;
	~AccessWiper() {
		std::visit([](auto &value) {
			using Value = std::decay_t<decltype(value)>;
			if constexpr (std::is_same_v<Value, AdminVaultAccess>
				|| std::is_same_v<Value, SetVaultAccess>) {
				CleanseKeys(value.accounts);
			}
			if constexpr (std::is_same_v<Value, SetVaultAccess>) {
				if (!value.settingsKey.isEmpty()) {
					OPENSSL_cleanse(value.settingsKey.data(), value.settingsKey.size());
				}
			}
		}, access);
	}
};

bool ValidateMappings(
		const AccountRegistry &registry,
		const std::vector<ProfileGenerationAccountBinding> &mappings) {
	auto entries = std::map<AccountId, const AccountRegistryEntry*>();
	for (const auto &entry : registry.entries) {
		if (!entry.retired) {
			entries.emplace(entry.id, &entry);
		}
	}
	if (entries.size() != mappings.size()) {
		return false;
	}
	auto ids = std::set<AccountId>();
	auto names = std::set<QString>();
	auto observedIdentities = std::set<QByteArray>();
	for (const auto &mapping : mappings) {
		const auto entry = entries.find(mapping.id);
		if (entry == end(entries)
			|| entry->second->slot != mapping.slot
			|| AccountRegistryDataNameHash(mapping.dataName)
				!= entry->second->legacyDataNameHash
			|| mapping.identities.empty()
			|| !ids.insert(mapping.id).second
			|| !names.insert(mapping.dataName).second) {
			return false;
		}
		auto matchedIdentity = false;
		for (const auto &identity : mapping.identities) {
			const auto fingerprint = RegistryIdentityFingerprint(identity);
			if (fingerprint.isEmpty()
				|| !observedIdentities.insert(fingerprint).second) {
				return false;
			}
			matchedIdentity = matchedIdentity || std::find(
				entry->second->identityFingerprints.cbegin(),
				entry->second->identityFingerprints.cend(),
				fingerprint) != entry->second->identityFingerprints.cend();
		}
		if (!matchedIdentity) {
			return false;
		}
	}
	return true;
}

bool AdminAccessMatchesKeyring(
		const AdminVaultAccess &access,
		const std::vector<AccountKey> &keyring) {
	if (access.accounts.size() != keyring.size()) {
		return false;
	}
	auto byId = std::map<AccountId, const AccountKey*>();
	for (const auto &key : keyring) {
		byId.emplace(key.id, &key);
	}
	for (const auto &key : access.accounts) {
		const auto i = byId.find(key.id);
		if (i == end(byId) || !EqualKey(i->second->key, key.key)) {
			return false;
		}
	}
	return true;
}

void CloseAdapters(std::vector<Fn<void()>> &adapters) {
	for (auto i = adapters.rbegin(); i != adapters.rend(); ++i) {
		(*i)();
	}
	adapters.clear();
}

} // namespace

OpenedProfileGeneration::OpenedProfileGeneration(
		AccountStoragePlan plan,
		ProfileGenerationAccess access,
		QByteArray transactionId,
		std::optional<Metadata> adminMetadata,
		QByteArray settingsKey,
		std::vector<AccountId> adminAccountIds)
: _plan(std::move(plan))
, _access(access)
, _transactionId(std::move(transactionId))
, _settingsKey(std::move(settingsKey))
, _adminMetadata(std::move(adminMetadata))
, _adminAccountIds(std::move(adminAccountIds)) {
}

OpenedProfileGeneration::OpenedProfileGeneration(
		OpenedProfileGeneration &&other) noexcept
: _plan(std::move(other._plan))
, _access(other._access)
, _transactionId(std::move(other._transactionId))
, _settingsKey(std::move(other._settingsKey))
, _closeAdapters(std::move(other._closeAdapters))
, _adminMetadata(std::move(other._adminMetadata))
, _adminAccountIds(std::move(other._adminAccountIds))
, _started(other._started)
, _closed(std::exchange(other._closed, true)) {
}

OpenedProfileGeneration::~OpenedProfileGeneration() {
	Close();
}

void OpenedProfileGeneration::Close() {
	if (_closed) {
		return;
	}
	CloseAdapters(_closeAdapters);
	_plan.Clear();
	_adminMetadata.reset();
	_adminAccountIds.clear();
	OPENSSL_cleanse(_settingsKey.data(), _settingsKey.size());
	_settingsKey.clear();
	_closed = true;
}

bool OpenedProfileGeneration::Start(
		const MigrationController &sidecar,
		StartProfileAccount startAccount,
		ProfileGenerationError *error) {
	return Start(sidecar, {}, std::move(startAccount), error);
}

bool OpenedProfileGeneration::Start(
		const MigrationController &sidecar,
		ValidateProfileAccount validateAccount,
		StartProfileAccount startAccount,
		ProfileGenerationError *error) {
	if (_closed || _started) {
		SetError(error, ProfileGenerationError::InvalidPlan);
		return false;
	}
	const auto fail = [&](ProfileGenerationError code) {
		SetError(error, code);
		Close();
		return false;
	};
	const auto start = [&] {
		const auto &targets = _plan.targets();
		if (!startAccount && !targets.empty()) {
			return fail(ProfileGenerationError::MissingAdapter);
		}
		for (const auto &target : targets) {
			const auto key = _plan.keyFor(target.id);
			if (!key) {
				return fail(ProfileGenerationError::InvalidPlan);
			} else if (validateAccount && !validateAccount(target, *key)) {
				return fail(ProfileGenerationError::ValidationFailed);
			}
		}
		for (const auto &target : targets) {
			const auto key = _plan.keyFor(target.id);
			Assert(key != nullptr);
			auto close = startAccount(target, *key);
			if (!close || !*close) {
				return fail(ProfileGenerationError::StartFailed);
			}
			_closeAdapters.push_back(std::move(*close));
		}
		return true;
	};
	auto migrationError = MigrationError::None;
	if (!sidecar.WithCurrentGeneration(_transactionId, start, &migrationError)) {
		if (migrationError == MigrationError::CallbackFailed) {
			return false;
		}
		return fail(migrationError == MigrationError::StaleGeneration
			? ProfileGenerationError::StaleGeneration
			: ProfileGenerationError::InvalidSidecar);
	}
	_started = true;
	SetError(error, ProfileGenerationError::None);
	return true;
}

std::optional<OpenedProfileGeneration> OpenCommittedProfileGeneration(
		const MigrationController &sidecar,
		DerivedCredential credential,
		StartProfileAccount startAccount,
		ProfileGenerationError *error) {
	return OpenCommittedProfileGeneration(
		sidecar,
		{},
		std::move(credential),
		{},
		{},
		{},
		{},
		std::move(startAccount),
		error);
}

std::optional<OpenedProfileGeneration> OpenCommittedProfileGeneration(
		const MigrationController &sidecar,
		GetAdminKeyringWrappingKey getAdminKeyringWrappingKey,
		DerivedCredential credential,
		const AccountRegistry &registry,
		const QByteArray &environmentId,
		std::vector<ProfileGenerationAccountBinding> mappings,
		QString globalTdataPath,
		StartProfileAccount startAccount,
		ProfileGenerationError *error) {
	auto authenticated = AuthenticateCommittedProfileGeneration(
		sidecar,
		std::move(getAdminKeyringWrappingKey),
		std::move(credential),
		registry,
		environmentId,
		std::move(mappings),
		std::move(globalTdataPath),
		{},
		error);
	if (authenticated && !authenticated->Start(
			sidecar, std::move(startAccount), error)) {
		return std::nullopt;
	}
	return authenticated;
}

std::optional<OpenedProfileGeneration> AuthenticateCommittedProfileGeneration(
		const MigrationController &sidecar,
		GetAdminKeyringWrappingKey getAdminKeyringWrappingKey,
		DerivedCredential credential,
		const AccountRegistry &registry,
		const QByteArray &environmentId,
		std::vector<ProfileGenerationAccountBinding> mappings,
		QString globalTdataPath,
		const QByteArray &expectedTransactionId,
		ProfileGenerationError *error) {
	SetError(error, ProfileGenerationError::NotCommitted);
	auto credentialWiper = CredentialWiper{ credential };
	MigrationError migrationError = MigrationError::None;
	if (sidecar.Recover(&migrationError) != MigrationState::Committed) {
		SetError(error, migrationError == MigrationError::None
			? ProfileGenerationError::NotCommitted
			: ProfileGenerationError::InvalidSidecar);
		return std::nullopt;
	}
	const auto committed = sidecar.LoadCommitted(&migrationError);
	if (!committed) {
		SetError(error, ProfileGenerationError::InvalidSidecar);
		return std::nullopt;
	}
	if (!committed->emergencyRecovery.isEmpty() || !committed->legacyRetirement.isEmpty()) {
		SetError(error, ProfileGenerationError::InvalidSidecar);
		return std::nullopt;
	}
	if (!expectedTransactionId.isEmpty()
		&& committed->transactionId != expectedTransactionId) {
		SetError(error, ProfileGenerationError::StaleGeneration);
		return std::nullopt;
	}
	auto vaultError = ProfileVaultError::Malformed;
	const auto vault = ParseProfileVault(committed->profileVault, &vaultError);
	if (!vault) {
		SetError(error, ProfileGenerationError::InvalidVault);
		return std::nullopt;
	}
	const auto legacy = (vault->version == kLegacyProfileVaultVersion);
	if (legacy) {
		if (!sidecar.isIsolatedFixture()) {
			SetError(error, ProfileGenerationError::InvalidVault);
			return std::nullopt;
		} else if (ValidateAccountRegistry(registry) != RegistryError::None
			|| registry.environmentId != environmentId) {
			SetError(error, ProfileGenerationError::InvalidRegistry);
			return std::nullopt;
		} else if (!ValidateMappings(registry, mappings)) {
			SetError(error, ProfileGenerationError::InvalidMappings);
			return std::nullopt;
		}
	}
	auto access = OpenProfileVault(*vault, credential, &vaultError);
	if (std::holds_alternative<WrongPassword>(access)) {
		SetError(error, (vaultError == ProfileVaultError::WrongPassword
			|| vaultError == ProfileVaultError::AuthenticationFailed)
			? ProfileGenerationError::WrongPassword
			: ProfileGenerationError::InvalidVault);
		return std::nullopt;
	}
	auto accessWiper = AccessWiper{ access };
	if (const auto admin = std::get_if<AdminVaultAccess>(&access)) {
		if (getAdminKeyringWrappingKey) {
			auto wrappingKey = getAdminKeyringWrappingKey();
			if (!wrappingKey) {
				SetError(error, ProfileGenerationError::InvalidKeyring);
				return std::nullopt;
			}
			auto wrappingKeyWiper = WrappingKeyWiper{ *wrappingKey };
			auto keyring = OpenAccountKeyring(
				committed->accountKeyring,
				*wrappingKey);
			if (!keyring) {
				SetError(error, ProfileGenerationError::InvalidKeyring);
				return std::nullopt;
			}
			auto keyringWiper = KeysWiper{ *keyring };
			if (!AdminAccessMatchesKeyring(*admin, *keyring)) {
				SetError(error, ProfileGenerationError::KeyMismatch);
				return std::nullopt;
			}
		}
		auto ids = std::vector<AccountId>();
		ids.reserve(admin->accounts.size());
		for (const auto &account : admin->accounts) {
			ids.push_back(account.id);
		}
		SetError(error, ProfileGenerationError::None);
		return OpenedProfileGeneration(
			AccountStoragePlan(),
			{ .role = ProfileGenerationRole::Master },
			committed->transactionId,
			std::move(admin->metadata),
			{},
			std::move(ids));
	}
	auto &set = std::get<SetVaultAccess>(access);
	const auto route = ProfileGenerationAccess{
		.role = ProfileGenerationRole::Set,
		.setId = set.id,
	};
	auto planError = AccountStoragePlanError::InvalidRoot;
	auto bindings = std::vector<AccountStorageBinding>();
	if (legacy) {
		bindings.reserve(mappings.size());
		for (const auto &mapping : mappings) {
			bindings.push_back({ .id = mapping.id, .dataName = mapping.dataName });
		}
	} else {
		globalTdataPath = sidecar.accountStorageRoot();
	}
	auto plan = BuildAccountStoragePlan(
		std::move(globalTdataPath),
		std::move(access),
		std::move(bindings),
		&planError);
	if (!plan) {
		SetError(error, (planError == AccountStoragePlanError::WrongPassword)
			? ProfileGenerationError::WrongPassword
			: ProfileGenerationError::InvalidPlan);
		return std::nullopt;
	}
	SetError(error, ProfileGenerationError::None);
	return OpenedProfileGeneration(
		std::move(*plan), route, committed->transactionId,
		std::nullopt, std::move(set.settingsKey));
}

ProfileGenerationError CommitProfileSetChange(
		const MigrationController &sidecar,
		const QByteArray &expectedTransactionId,
		const ProfileSetChange &change,
		DerivedCredential admin,
		std::optional<DerivedCredential> replacement) {
	using Error = ProfileGenerationError;
	using Kind = ProfileSetChangeKind;
	auto adminWiper = CredentialWiper{ admin };
	const auto replacementWiper = gsl::finally([&] {
		if (replacement) {
			CleanseCredential(*replacement);
		}
	});
	const auto current = !sidecar.isIsolatedFixture()
		? sidecar.LoadCommitted()
		: std::nullopt;
	if (!current) {
		return Error::InvalidSidecar;
	} else if (current->transactionId != expectedTransactionId) {
		return Error::StaleGeneration;
	}
	const auto vault = ParseProfileVault(current->profileVault);
	if (!vault || vault->version != kProfileVaultVersion) {
		return Error::InvalidVault;
	} else if (!admin.valid() || !EqualKey(admin.verifier, vault->adminVerifier)) {
		return Error::WrongPassword;
	}
	auto opened = OpenProfileVault(*vault, admin);
	auto accessWiper = AccessWiper{ opened };
	const auto master = std::get_if<AdminVaultAccess>(&opened);
	if (!master) {
		return Error::InvalidVault;
	}

	auto &metadata = master->metadata;
	auto i = std::ranges::find(
		metadata.sets,
		change.id.value_or(SetId()),
		&AccountSet::id);
	auto replacements = std::vector<SetGrantCredential>();
	if (change.kind == Kind::Remove) {
		if (i == end(metadata.sets) || replacement
			|| !change.name.isEmpty() || !change.accounts.empty()) {
			return Error::SettingsRejected;
		}
		metadata.sets.erase(i);
	} else {
		const auto adding = (change.kind == Kind::Add);
		if ((adding && (change.id || !replacement))
			|| (!adding && (change.kind != Kind::Edit || i == end(metadata.sets)))) {
			return Error::SettingsRejected;
		} else if (replacement
			&& !std::holds_alternative<WrongPassword>(RoutePasswordVerifier(
				metadata,
				replacement->verifier))) {
			return Error::PasswordInUse;
		}
		if (adding) {
			i = metadata.sets.insert(end(metadata.sets), AccountSet{
				.id = NewSetId(),
			});
		}
		i->name = change.name.trimmed();
		i->accounts = change.accounts;
		if (replacement) {
			i->verifier = replacement->verifier;
			replacements.push_back({
				.id = i->id,
				.credential = std::move(*replacement),
			});
		}
	}
	auto error = Error::None;
	const auto saved = CommitProfileSetChanges(
		sidecar,
		expectedTransactionId,
		std::move(admin),
		metadata,
		std::move(replacements),
		&error);
	return saved ? Error::None : error;
}

std::optional<QByteArray> CommitProfileSetChanges(
		const MigrationController &sidecar,
		const QByteArray &expectedTransactionId,
		DerivedCredential admin,
		const Metadata &metadata,
		std::vector<SetGrantCredential> replacements,
		ProfileGenerationError *error) {
	auto adminWiper = CredentialWiper{ admin };
	const auto replacementsWiper = gsl::finally([&] {
		for (auto &replacement : replacements) {
			CleanseCredential(replacement.credential);
		}
	});
	const auto current = sidecar.LoadCommitted();
	if (!current || sidecar.isIsolatedFixture()) {
		SetError(error, ProfileGenerationError::InvalidSidecar);
		return std::nullopt;
	} else if (current->transactionId != expectedTransactionId) {
		SetError(error, ProfileGenerationError::StaleGeneration);
		return std::nullopt;
	} else if (!current->emergencyRules.isEmpty()
		|| !current->legacyRetirement.isEmpty()) {
		SetError(error, ProfileGenerationError::SettingsRejected);
		return std::nullopt;
	}
	const auto vault = ParseProfileVault(current->profileVault);
	if (!vault || vault->version != kProfileVaultVersion) {
		SetError(error, ProfileGenerationError::InvalidVault);
		return std::nullopt;
	}
	auto vaultError = ProfileVaultError::None;
	const auto updated = UpdateProfileVault(
		*vault, admin, metadata, replacements, &vaultError);
	if (!updated) {
		SetError(error, (vaultError == ProfileVaultError::WrongPassword)
			? ProfileGenerationError::WrongPassword
			: ProfileGenerationError::SettingsRejected);
		return std::nullopt;
	}
	auto migrationError = MigrationError::None;
	const auto committed = sidecar.ReplaceCommitted(
		expectedTransactionId,
		{
			{ MigrationArtifact::ProfileVault, SerializeProfileVault(*updated) },
			{ MigrationArtifact::AccountKeyring, current->accountKeyring },
		},
		[&](const CommittedMigration &candidate) {
			const auto decoded = ParseProfileVault(candidate.profileVault);
			if (!decoded || candidate.accountKeyring != current->accountKeyring) {
				return false;
			}
			auto opened = OpenProfileVault(*decoded, admin);
			auto wiper = AccessWiper{ opened };
			const auto master = std::get_if<AdminVaultAccess>(&opened);
			return master && master->metadata == metadata;
		},
		&migrationError);
	if (!committed) {
		const auto code = (migrationError == MigrationError::StaleGeneration)
			? ProfileGenerationError::StaleGeneration
			: (migrationError == MigrationError::PublicationUncertain)
			? ProfileGenerationError::PublicationUncertain
			: ProfileGenerationError::InvalidSidecar;
		SetError(error, code);
		return std::nullopt;
	}
	SetError(error, ProfileGenerationError::None);
	return committed->transactionId;
}

} // namespace Ayu::ProfileSets
