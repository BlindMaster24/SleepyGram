/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ayu/features/profile_sets/account_registry.h"
#include "ayu/features/profile_sets/account_storage_plan.h"
#include "ayu/features/profile_sets/profile_migration.h"

#include <optional>
#include <vector>

namespace Ayu::ProfileSets {

struct ProfileGenerationAccountBinding final {
	AccountId id;
	QString dataName;
	quint32 slot = 0;
	std::vector<VerifiedRegistryIdentity> identities;
};

enum class ProfileGenerationRole : uchar {
	Master,
	Set,
};

struct ProfileGenerationAccess final {
	ProfileGenerationRole role = ProfileGenerationRole::Master;
	std::optional<SetId> setId;
};

enum class ProfileGenerationError : uchar {
	None,
	NotCommitted,
	InvalidSidecar,
	InvalidVault,
	InvalidKeyring,
	WrongPassword,
	InvalidRegistry,
	InvalidMappings,
	KeyMismatch,
	InvalidPlan,
	MissingAdapter,
	StartFailed,
	StaleGeneration,
	DerivationFailed,
	ValidationFailed,
	SettingsRejected,
	PublicationUncertain,
	PasswordInUse,
};

// A failed start must leave no live account; success returns its close action.
using StartProfileAccount = Fn<std::optional<Fn<void()>>(
	const AccountStorageTarget&,
	const AccountKey&)>;
using ValidateProfileAccount = Fn<bool(
	const AccountStorageTarget&,
	const AccountKey&)>;
using GetAdminKeyringWrappingKey = Fn<std::optional<QByteArray>()>;

class OpenedProfileGeneration final {
public:
	OpenedProfileGeneration(OpenedProfileGeneration &&other) noexcept;
	OpenedProfileGeneration &operator=(OpenedProfileGeneration&&) = delete;
	OpenedProfileGeneration(const OpenedProfileGeneration&) = delete;
	OpenedProfileGeneration &operator=(const OpenedProfileGeneration&) = delete;
	~OpenedProfileGeneration();

	[[nodiscard]] const AccountStoragePlan &plan() const {
		return _plan;
	}
	[[nodiscard]] ProfileGenerationAccess access() const {
		return _access;
	}
	[[nodiscard]] const QByteArray &transactionId() const {
		return _transactionId;
	}
	[[nodiscard]] const QByteArray &settingsKey() const {
		return _settingsKey;
	}
	[[nodiscard]] const Metadata *adminMetadata() const {
		return _adminMetadata ? &*_adminMetadata : nullptr;
	}
	[[nodiscard]] const std::vector<AccountId> &adminAccountIds() const {
		return _adminAccountIds;
	}
	[[nodiscard]] bool Start(
		const MigrationController &sidecar,
		StartProfileAccount startAccount,
		ProfileGenerationError *error = nullptr);
	[[nodiscard]] bool Start(
		const MigrationController &sidecar,
		ValidateProfileAccount validateAccount,
		StartProfileAccount startAccount,
		ProfileGenerationError *error = nullptr);
	void Close();

private:
	friend std::optional<OpenedProfileGeneration>
	AuthenticateCommittedProfileGeneration(
		const MigrationController&,
		GetAdminKeyringWrappingKey,
		DerivedCredential,
		const AccountRegistry&,
		const QByteArray&,
		std::vector<ProfileGenerationAccountBinding>,
		QString,
		const QByteArray&,
		ProfileGenerationError*);

	OpenedProfileGeneration(
		AccountStoragePlan plan,
		ProfileGenerationAccess access,
		QByteArray transactionId,
		std::optional<Metadata> adminMetadata = std::nullopt,
		QByteArray settingsKey = {},
		std::vector<AccountId> adminAccountIds = {});

	AccountStoragePlan _plan;
	ProfileGenerationAccess _access;
	QByteArray _transactionId;
	QByteArray _settingsKey;
	std::vector<Fn<void()>> _closeAdapters;
	std::optional<Metadata> _adminMetadata;
	std::vector<AccountId> _adminAccountIds;
	bool _started = false;
	bool _closed = false;

};

[[nodiscard]] std::optional<OpenedProfileGeneration>
AuthenticateCommittedProfileGeneration(
	const MigrationController &sidecar,
	GetAdminKeyringWrappingKey getAdminKeyringWrappingKey,
	DerivedCredential credential,
	const AccountRegistry &registry,
	const QByteArray &environmentId,
	std::vector<ProfileGenerationAccountBinding> mappings,
	QString globalTdataPath,
	const QByteArray &expectedTransactionId,
	ProfileGenerationError *error = nullptr);

using ProfilePasswordDone = Fn<void(
	std::optional<OpenedProfileGeneration>,
	ProfileGenerationError)>;

void AuthenticateScopedProfilePasscode(
	MigrationController sidecar,
	QString passcode,
	ProfilePasswordDone done);

enum class ProfileSetChangeKind : uchar {
	Add,
	Edit,
	Remove,
};

struct ProfileSetChange final {
	ProfileSetChangeKind kind = ProfileSetChangeKind::Edit;
	std::optional<SetId> id;
	QString name;
	std::vector<AccountId> accounts;
};

void SaveProfileSetChange(
	MigrationController sidecar,
	QByteArray expectedTransactionId,
	ProfileSetChange change,
	QString masterPasscode,
	QString setPasscode,
	Fn<void(ProfileGenerationError)> done);

[[nodiscard]] ProfileGenerationError CommitProfileSetChange(
	const MigrationController &sidecar,
	const QByteArray &expectedTransactionId,
	const ProfileSetChange &change,
	DerivedCredential admin,
	std::optional<DerivedCredential> replacement);

[[nodiscard]] std::optional<QByteArray> CommitProfileSetChanges(
	const MigrationController &sidecar,
	const QByteArray &expectedTransactionId,
	DerivedCredential admin,
	const Metadata &metadata,
	std::vector<SetGrantCredential> replacements,
	ProfileGenerationError *error = nullptr);

[[nodiscard]] std::optional<OpenedProfileGeneration>
OpenCommittedProfileGeneration(
	const MigrationController &sidecar,
	DerivedCredential credential,
	StartProfileAccount startAccount,
	ProfileGenerationError *error = nullptr);

// Bindings must come from the current verified account observation.
[[nodiscard]] std::optional<OpenedProfileGeneration>
OpenCommittedProfileGeneration(
	const MigrationController &sidecar,
	GetAdminKeyringWrappingKey getAdminKeyringWrappingKey,
	DerivedCredential credential,
	const AccountRegistry &registry,
	const QByteArray &environmentId,
	std::vector<ProfileGenerationAccountBinding> mappings,
	QString globalTdataPath,
	StartProfileAccount startAccount,
	ProfileGenerationError *error = nullptr);

} // namespace Ayu::ProfileSets
