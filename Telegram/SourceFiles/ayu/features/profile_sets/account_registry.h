/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ayu/features/profile_sets/profile_sets.h"

#include <optional>
#include <vector>

namespace Ayu::ProfileSets {

inline constexpr auto kAccountRegistryVersion = quint32(1);

enum class RegistryIdentityKind : uchar {
	ServerUserId = 1,
	VerifiedLocator = 2,
};

struct VerifiedRegistryIdentity final {
	RegistryIdentityKind kind = RegistryIdentityKind::ServerUserId;
	QByteArray value;
};

struct ObservedLegacyAccount final {
	QString dataName;
	quint32 slot = 0;
	std::vector<VerifiedRegistryIdentity> identities;
};

struct AccountRegistryEntry final {
	AccountId id;
	QByteArray legacyDataNameHash;
	quint32 slot = 0;
	std::vector<QByteArray> identityFingerprints;
	bool retired = false;

	friend inline bool operator==(const AccountRegistryEntry&,
		const AccountRegistryEntry&) = default;
};

struct AccountRegistry final {
	quint32 version = kAccountRegistryVersion;
	QByteArray environmentId;
	std::vector<AccountRegistryEntry> entries;

	friend inline bool operator==(const AccountRegistry&,
		const AccountRegistry&) = default;
};

enum class RegistryError : uchar {
	None,
	InvalidEnvironment,
	EnvironmentMismatch,
	InvalidIdentity,
	DuplicateObservedIdentity,
	DuplicateObservedLocator,
	DuplicateAccountId,
	DuplicateIdentityFingerprint,
	InvalidEntry,
	TooLarge,
	RandomFailure,
	Malformed,
	UnsupportedVersion,
};

[[nodiscard]] std::optional<AccountRegistry> NewAccountRegistry(
	QByteArray environmentId,
	RegistryError *error = nullptr);
[[nodiscard]] RegistryError ValidateAccountRegistry(
	const AccountRegistry &registry);
[[nodiscard]] QByteArray SerializeAccountRegistry(
	const AccountRegistry &registry,
	RegistryError *error = nullptr);
[[nodiscard]] std::optional<AccountRegistry> ParseAccountRegistry(
	const QByteArray &payload,
	RegistryError *error = nullptr);
[[nodiscard]] std::optional<AccountRegistry> ReconcileAccountRegistry(
	const AccountRegistry &registry,
	const QByteArray &environmentId,
	const std::vector<ObservedLegacyAccount> &observed,
	Fn<AccountId()> generateId = [] { return NewAccountId(); },
	RegistryError *error = nullptr);
[[nodiscard]] RegistryError BindRegistryIdentity(
	AccountRegistry *registry,
	AccountId accountId,
	const VerifiedRegistryIdentity &identity);
[[nodiscard]] QByteArray RegistryIdentityFingerprint(
	const VerifiedRegistryIdentity &identity);
[[nodiscard]] QByteArray AccountRegistryDataNameHash(const QString &dataName);

} // namespace Ayu::ProfileSets
