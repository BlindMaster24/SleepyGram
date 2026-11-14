/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ayu/features/profile_sets/account_keyring.h"

namespace Ayu::ProfileSets {

inline constexpr auto kProfileVaultVersion = quint32(1);
inline constexpr auto kProfileVaultKeySize = 32;
inline constexpr auto kProfileVaultIdSize = 16;

struct DerivedCredential final {
	QByteArray verifier;
	QByteArray key;

	[[nodiscard]] bool valid() const noexcept {
		return verifier.size() == kVerifierSize
			&& key.size() == kProfileVaultKeySize
			&& !verifier.isEmpty()
			&& !key.isEmpty();
	}
};

struct SetGrantCredential final {
	SetId id;
	DerivedCredential credential;
};

struct SealedSetGrant final {
	SetId id;
	QByteArray verifier;
	QByteArray nonce;
	QByteArray ciphertext;

	friend inline bool operator==(const SealedSetGrant&, const SealedSetGrant&) = default;
};

struct ProfileVault final {
	quint32 version = kProfileVaultVersion;
	QByteArray id;
	QByteArray salt;
	KdfParameters kdf;
	QByteArray adminVerifier;
	QByteArray adminNonce;
	QByteArray adminCiphertext;
	std::vector<SealedSetGrant> grants;
};

struct AdminVaultAccess final {
	Metadata metadata;
	std::vector<AccountKey> accounts;
};

struct SetVaultAccess final {
	SetId id;
	std::vector<AccountKey> accounts;
};

using ProfileVaultAccess = std::variant<
	WrongPassword,
	AdminVaultAccess,
	SetVaultAccess>;

enum class ProfileVaultError : uchar {
	None,
	InvalidKdf,
	InvalidVaultId,
	InvalidCredential,
	WrongPassword,
	MetadataMismatch,
	InvalidGrant,
	AuthenticationFailed,
	Malformed,
	UnsupportedVersion,
	TooLarge,
	RandomFailure,
};

[[nodiscard]] bool ValidProfileVaultKdf(KdfParameters kdf);
void DeriveProfileVaultCredential(
	QByteArray salt,
	KdfParameters kdf,
	QString password,
	Fn<void(DerivedCredential)> done);
[[nodiscard]] std::optional<ProfileVault> SealProfileVault(
	const Metadata &metadata,
	const std::vector<AccountKey> &accounts,
	const DerivedCredential &admin,
	const std::vector<SetGrantCredential> &grants,
	ProfileVaultError *error = nullptr);
[[nodiscard]] ProfileVaultAccess OpenProfileVault(
	const ProfileVault &vault,
	const DerivedCredential &credential,
	ProfileVaultError *error = nullptr);
[[nodiscard]] QByteArray SerializeProfileVault(
	const ProfileVault &vault,
	ProfileVaultError *error = nullptr);
[[nodiscard]] std::optional<ProfileVault> ParseProfileVault(
	const QByteArray &serialized,
	ProfileVaultError *error = nullptr);

} // namespace Ayu::ProfileSets
