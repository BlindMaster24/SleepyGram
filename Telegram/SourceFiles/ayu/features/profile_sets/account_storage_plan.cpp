/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/account_storage_plan.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <map>
#include <set>
#include <type_traits>

#include <QtCore/QDir>

namespace Ayu::ProfileSets {
namespace {

void SetError(AccountStoragePlanError *error, AccountStoragePlanError value) {
	if (error) {
		*error = value;
	}
}

void ClearKeys(std::vector<AccountKey> &keys) {
	for (auto &key : keys) {
		if (!key.key.isEmpty()) {
			OPENSSL_cleanse(key.key.data(), size_t(key.key.size()));
		}
	}
}

bool SafeDataName(const QString &name) {
	if (name.isEmpty() || name.size() > 128) {
		return false;
	}
	return std::all_of(name.cbegin(), name.cend(), [](QChar ch) {
		return (ch >= QLatin1Char('a') && ch <= QLatin1Char('z'))
			|| (ch >= QLatin1Char('A') && ch <= QLatin1Char('Z'))
			|| (ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
			|| ch == QLatin1Char('_')
			|| ch == QLatin1Char('-');
	});
}

struct KeyWiper final {
	std::vector<AccountKey> &keys;
	~KeyWiper() {
		ClearKeys(keys);
	}
};

} // namespace

AccountStoragePlan::~AccountStoragePlan() {
	ClearKeys(_keys);
}

const AccountStorageTarget *AccountStoragePlan::targetFor(AccountId id) const {
	const auto i = std::ranges::find(_targets, id, &AccountStorageTarget::id);
	return (i == end(_targets)) ? nullptr : &*i;
}

const AccountKey *AccountStoragePlan::keyFor(AccountId id) const {
	if (!targetFor(id)) {
		return nullptr;
	}
	const auto i = std::ranges::find(_keys, id, &AccountKey::id);
	return (i == end(_keys)) ? nullptr : &*i;
}

std::optional<AccountStoragePlan> BuildAccountStoragePlan(
		QString globalTdataPath,
		ProfileVaultAccess &&access,
		std::vector<AccountStorageBinding> bindings,
		AccountStoragePlanError *error) {
	SetError(error, AccountStoragePlanError::InvalidRoot);
	if (globalTdataPath.isEmpty()
		|| !QDir::isAbsolutePath(globalTdataPath)
		|| globalTdataPath.contains(QChar(0))) {
		return std::nullopt;
	}
	globalTdataPath = QDir::cleanPath(globalTdataPath);
	if (!globalTdataPath.endsWith('/')) {
		globalTdataPath += '/';
	}

	auto keys = std::visit([](auto &grant) {
		using Grant = std::decay_t<decltype(grant)>;
		if constexpr (std::is_same_v<Grant, AdminVaultAccess>
			|| std::is_same_v<Grant, SetVaultAccess>) {
			return std::move(grant.accounts);
		} else {
			return std::vector<AccountKey>();
		}
	}, access);
	auto wipe = KeyWiper{ keys };
	if (std::holds_alternative<WrongPassword>(access)) {
		SetError(error, AccountStoragePlanError::WrongPassword);
		return std::nullopt;
	}
	if (ValidateAccountKeys(keys) != KeyringError::None) {
		SetError(error, AccountStoragePlanError::InvalidKeys);
		return std::nullopt;
	}

	auto bindingsById = std::map<AccountId, const AccountStorageBinding*>();
	auto names = std::set<QString>();
	for (const auto &binding : bindings) {
		if (!binding.id || !SafeDataName(binding.dataName)
			|| !names.insert(binding.dataName).second
			|| !bindingsById.emplace(binding.id, &binding).second) {
			SetError(error, AccountStoragePlanError::InvalidBindings);
			return std::nullopt;
		}
	}

	auto result = AccountStoragePlan();
	auto targetPaths = std::set<QString>();
	result._keys = std::move(keys);
	for (const auto &key : result._keys) {
		const auto binding = bindingsById.find(key.id);
		if (binding == end(bindingsById)) {
			SetError(error, AccountStoragePlanError::MissingBinding);
			return std::nullopt;
		}
		const auto paths = Storage::AccountPathsForDataName(
			globalTdataPath,
			binding->second->dataName);
		if (!targetPaths.insert(paths.basePath).second
			|| !targetPaths.insert(paths.tempPath).second
			|| !targetPaths.insert(paths.databasePath).second) {
			SetError(error, AccountStoragePlanError::PathCollision);
			return std::nullopt;
		}
		result._targets.push_back({
			.id = key.id,
			.dataName = binding->second->dataName,
			.paths = paths,
		});
	}
	std::ranges::sort(result._targets, {}, &AccountStorageTarget::id);
	SetError(error, AccountStoragePlanError::None);
	return std::optional<AccountStoragePlan>(std::move(result));
}

} // namespace Ayu::ProfileSets
