/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ayu/features/profile_sets/account_keyring.h"

namespace Ayu::ProfileSets {

inline constexpr auto kLegacyProfileVaultVersion = quint32(1);
inline constexpr auto kProfileVaultVersion = quint32(2);
inline constexpr auto kProfileVaultKeySize = 32;
inline constexpr auto kProfileVaultIdSize = 16;
inline constexpr auto kAccountVaultLocatorSize = 16;

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

namespace details {

[[nodiscard]] bool ValidProfileVaultSalt(const QByteArray &salt);
[[nodiscard]] DerivedCredential ProfileVaultCredentialFromKdfOutput(
	QByteArrayView material);

} // namespace details

struct SetGrantCredential final {
	SetId id;
	DerivedCredential credential;
};

struct AccountVaultLocator final {
	AccountId id;
	QByteArray value;

	friend inline bool operator==(
		const AccountVaultLocator&,
		const AccountVaultLocator&) = default;
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
	std::vector<AccountVaultLocator> locators;
	quint32 version = kProfileVaultVersion;
};

struct SetVaultAccess final {
	SetId id;
	std::vector<AccountKey> accounts;
	std::vector<AccountVaultLocator> locators;
	quint32 version = kProfileVaultVersion;
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
[[nodiscard]] std::optional<AccountVaultLocator> NewAccountVaultLocator(
	AccountId id);
[[nodiscard]] QString AccountVaultDataName(const AccountVaultLocator &locator);
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
[[nodiscard]] std::optional<ProfileVault> SealProfileVault(
	const Metadata &metadata,
	const std::vector<AccountKey> &accounts,
	const std::vector<AccountVaultLocator> &locators,
	const DerivedCredential &admin,
	const std::vector<SetGrantCredential> &grants,
	ProfileVaultError *error = nullptr);
// A replacement credential is required for each added set or changed passcode.
[[nodiscard]] std::optional<ProfileVault> UpdateProfileVault(
	const ProfileVault &vault,
	const DerivedCredential &admin,
	const Metadata &metadata,
	const std::vector<SetGrantCredential> &replacementCredentials,
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
