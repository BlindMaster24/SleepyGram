/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_generation.h"

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
		std::vector<Fn<void()>> closeAdapters,
		std::optional<Metadata> adminMetadata)
: _plan(std::move(plan))
, _access(access)
, _closeAdapters(std::move(closeAdapters))
, _adminMetadata(std::move(adminMetadata)) {
}

OpenedProfileGeneration::OpenedProfileGeneration(
		OpenedProfileGeneration &&other) noexcept
: _plan(std::move(other._plan))
, _access(other._access)
, _closeAdapters(std::move(other._closeAdapters))
, _adminMetadata(std::move(other._adminMetadata))
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
	_closed = true;
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
		SetError(error, ProfileGenerationError::None);
		return OpenedProfileGeneration(
			AccountStoragePlan(),
			{ .role = ProfileGenerationRole::Master },
			{},
			std::move(admin->metadata));
	}
	const auto route = ProfileGenerationAccess{
		.role = ProfileGenerationRole::Set,
		.setId = std::get<SetVaultAccess>(access).id,
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
	if (!startAccount && !plan->targets().empty()) {
		SetError(error, ProfileGenerationError::MissingAdapter);
		return std::nullopt;
	}
	auto closeAdapters = std::vector<Fn<void()>>();
	for (const auto &target : plan->targets()) {
		const auto key = plan->keyFor(target.id);
		if (!key) {
			CloseAdapters(closeAdapters);
			SetError(error, ProfileGenerationError::InvalidPlan);
			return std::nullopt;
		}
		auto close = startAccount(target, *key);
		if (!close || !*close) {
			CloseAdapters(closeAdapters);
			SetError(error, ProfileGenerationError::StartFailed);
			return std::nullopt;
		}
		closeAdapters.push_back(std::move(*close));
	}
	auto opened = OpenedProfileGeneration(
		std::move(*plan),
		route,
		std::move(closeAdapters));
	SetError(error, ProfileGenerationError::None);
	return std::optional<OpenedProfileGeneration>(std::move(opened));
}

} // namespace Ayu::ProfileSets
