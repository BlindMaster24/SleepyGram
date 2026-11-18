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
};

// A failed start must leave no live account; success returns its close action.
using StartProfileAccount = Fn<std::optional<Fn<void()>>(
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
	[[nodiscard]] const Metadata *adminMetadata() const {
		return _adminMetadata ? &*_adminMetadata : nullptr;
	}
	void Close();

private:
	friend std::optional<OpenedProfileGeneration>
	OpenCommittedProfileGeneration(
		const MigrationController&,
		GetAdminKeyringWrappingKey,
		DerivedCredential,
		const AccountRegistry&,
		const QByteArray&,
		std::vector<ProfileGenerationAccountBinding>,
		QString,
		StartProfileAccount,
		ProfileGenerationError*);

	OpenedProfileGeneration(
		AccountStoragePlan plan,
		ProfileGenerationAccess access,
		std::vector<Fn<void()>> closeAdapters,
		std::optional<Metadata> adminMetadata = std::nullopt);

	AccountStoragePlan _plan;
	ProfileGenerationAccess _access;
	std::vector<Fn<void()>> _closeAdapters;
	std::optional<Metadata> _adminMetadata;
	bool _closed = false;

};

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
