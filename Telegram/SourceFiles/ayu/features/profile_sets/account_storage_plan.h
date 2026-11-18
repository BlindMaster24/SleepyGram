/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ayu/features/profile_sets/profile_vault.h"
#include "storage/storage_account_paths.h"

#include <optional>
#include <vector>

namespace Ayu::ProfileSets {

struct AccountStorageBinding final {
	AccountId id;
	QString dataName;
};

struct AccountStorageTarget final {
	AccountId id;
	QString dataName;
	Storage::AccountPaths paths;
};

enum class AccountStoragePlanError : uchar {
	None,
	WrongPassword,
	InvalidRoot,
	InvalidKeys,
	InvalidBindings,
	MissingBinding,
	PathCollision,
};

class AccountStoragePlan final {
public:
	AccountStoragePlan() = default;
	AccountStoragePlan(AccountStoragePlan &&other) noexcept = default;
	AccountStoragePlan &operator=(AccountStoragePlan &&other) noexcept = delete;
	AccountStoragePlan(const AccountStoragePlan&) = delete;
	AccountStoragePlan &operator=(const AccountStoragePlan&) = delete;
	~AccountStoragePlan();

	[[nodiscard]] const std::vector<AccountStorageTarget> &targets() const {
		return _targets;
	}
	[[nodiscard]] const AccountStorageTarget *targetFor(AccountId id) const;
	[[nodiscard]] const AccountKey *keyFor(AccountId id) const;
	void Clear();

private:
	friend std::optional<AccountStoragePlan> BuildAccountStoragePlan(
		QString,
		ProfileVaultAccess&&,
		std::vector<AccountStorageBinding>,
		AccountStoragePlanError*);

	std::vector<AccountStorageTarget> _targets;
	std::vector<AccountKey> _keys;
};

// Pass the access result directly from OpenProfileVault; this variant is not
// an unforgeable capability on its own.
[[nodiscard]] std::optional<AccountStoragePlan> BuildAccountStoragePlan(
	QString rootPath,
	ProfileVaultAccess &&access,
	std::vector<AccountStorageBinding> bindings,
	AccountStoragePlanError *error = nullptr);

} // namespace Ayu::ProfileSets
