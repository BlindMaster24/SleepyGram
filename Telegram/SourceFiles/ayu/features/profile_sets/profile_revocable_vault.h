// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/account_gate_table.h"
#include "ayu/features/profile_sets/profile_vault.h"

namespace Ayu::ProfileSets {

inline constexpr auto kRevocableProfileVaultVersion = quint32(3);

struct RevocableAccountGrant final {
	AccountGateHandle handle;
	AccountGateRevocationPermit permit;
};

struct RevocableAdminVaultAccess final {
	Metadata metadata;
	std::vector<RevocableAccountGrant> accounts;
};

class RevocableSetVaultAccess final {
public:
	RevocableSetVaultAccess(RevocableSetVaultAccess &&other) noexcept;
	~RevocableSetVaultAccess();

	[[nodiscard]] SetId id() const;
	[[nodiscard]] const std::vector<AccountGateHandle> &handles() const;
	[[nodiscard]] QByteArrayView settingsKey() const;

private:
	friend class RevocableProfileVault;

	RevocableSetVaultAccess(
		SetId id,
		std::vector<AccountGateHandle> handles,
		QByteArray settingsKey);

	SetId _id;
	std::vector<AccountGateHandle> _handles;
	QByteArray _settingsKey;

};

using RevocableProfileVaultAccess = std::variant<
	WrongPassword,
	RevocableAdminVaultAccess,
	RevocableSetVaultAccess>;

class RevocableProfileVault final {
public:
	[[nodiscard]] static std::optional<RevocableProfileVault> Seal(
		QByteArrayView installationId,
		const Metadata &metadata,
		std::span<const RevocableAccountGrant> accounts,
		const DerivedCredential &admin,
		const std::vector<SetGrantCredential> &credentials,
		ProfileVaultError *error = nullptr);
	[[nodiscard]] static std::optional<RevocableProfileVault> Parse(
		const QByteArray &bytes,
		ProfileVaultError *error = nullptr);

	[[nodiscard]] const QByteArray &installationId() const;
	[[nodiscard]] const QByteArray &salt() const;
	[[nodiscard]] KdfParameters kdf() const;
	[[nodiscard]] QByteArray serialize(ProfileVaultError *error = nullptr) const;
	[[nodiscard]] RevocableProfileVaultAccess open(
		const DerivedCredential &credential,
		ProfileVaultError *error = nullptr) const;
	[[nodiscard]] std::optional<RevocableAdminVaultAccess> openMaster(
		const DerivedCredential &credential,
		ProfileVaultError *error = nullptr) const;
	[[nodiscard]] std::optional<RevocableProfileVault> updated(
		const DerivedCredential &admin,
		const Metadata &metadata,
		const std::vector<SetGrantCredential> &replacements,
		ProfileVaultError *error = nullptr) const;
	[[nodiscard]] std::optional<RevocableProfileVault> enrolled(
		const DerivedCredential &admin,
		SetId target,
		const DerivedCredential &setCredential,
		const AccountGateTable &currentGates,
		RevocableAccountGrant account,
		QString newSetName,
		ProfileVaultError *error = nullptr) const;

private:
	explicit RevocableProfileVault(ProfileVault envelope);

	ProfileVault _envelope;

};

namespace details {

[[nodiscard]] ProfileVaultError ValidateRevocableProfileEnvelope(const ProfileVault &envelope);
[[nodiscard]] QByteArray SerializeRevocableProfileEnvelope(
	const ProfileVault &envelope,
	ProfileVaultError *error);
[[nodiscard]] std::optional<ProfileVault> ParseRevocableProfileEnvelope(
	const QByteArray &bytes,
	ProfileVaultError *error);
[[nodiscard]] bool ValidRevocableProfileCredential(const DerivedCredential &credential);
[[nodiscard]] QByteArray RevocableProfileEnvelopeKey(
	const ProfileVault &envelope,
	SetId id,
	const DerivedCredential &credential);
[[nodiscard]] QByteArray RevocableProfileGrantManifest(const ProfileVault &envelope);
[[nodiscard]] QByteArray RevocableProfileSettingsKey(
	const ProfileVault &envelope,
	SetId id,
	const DerivedCredential &admin);
[[nodiscard]] std::optional<SealedSetGrant> SealRevocableProfileGrant(
	const ProfileVault &envelope,
	SetId id,
	const QByteArray &verifier,
	const QByteArray &key,
	const QByteArray &plaintext);
[[nodiscard]] QByteArray OpenRevocableProfileGrant(
	const ProfileVault &envelope,
	const SealedSetGrant &grant,
	const QByteArray &key);

} // namespace details
} // namespace Ayu::ProfileSets
