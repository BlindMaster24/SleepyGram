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
	Clear();
}

void AccountStoragePlan::Clear() {
	ClearKeys(_keys);
	_keys.clear();
	_targets.clear();
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
		QString rootPath,
		ProfileVaultAccess &&access,
		std::vector<AccountStorageBinding> bindings,
		AccountStoragePlanError *error) {
	SetError(error, AccountStoragePlanError::InvalidRoot);
	if (!QDir::isAbsolutePath(rootPath)
		|| rootPath.startsWith(':')
		|| rootPath.contains(QChar(0))) {
		return std::nullopt;
	}
	rootPath = QDir::cleanPath(rootPath);

	const auto admin = std::get_if<AdminVaultAccess>(&access);
	const auto set = std::get_if<SetVaultAccess>(&access);
	if (!admin && !set) {
		SetError(error, AccountStoragePlanError::WrongPassword);
		return std::nullopt;
	}
	auto keys = std::move(admin ? admin->accounts : set->accounts);
	auto wipe = KeyWiper{ keys };
	if (ValidateAccountKeys(keys) != KeyringError::None) {
		SetError(error, AccountStoragePlanError::InvalidKeys);
		return std::nullopt;
	}
	const auto version = admin ? admin->version : set->version;
	const auto scoped = (version == kProfileVaultVersion);
	const auto &locators = admin ? admin->locators : set->locators;
	SetError(error, AccountStoragePlanError::InvalidBindings);
	if (scoped) {
		if (!bindings.empty() || locators.size() != keys.size()) {
			return std::nullopt;
		}
		if (admin) {
			SetError(error, AccountStoragePlanError::None);
			return AccountStoragePlan();
		}
		bindings.reserve(locators.size());
		for (const auto &locator : locators) {
			bindings.push_back({
				.id = locator.id,
				.dataName = AccountVaultDataName(locator),
			});
		}
	} else if (version != kLegacyProfileVaultVersion || !locators.empty()) {
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
		const auto &dataName = binding->second->dataName;
		auto paths = scoped
			? Storage::ScopedAccountPaths(rootPath, dataName)
			: std::optional(Storage::AccountPathsForDataName(
				rootPath,
				dataName));
		if (!paths) {
			SetError(error, AccountStoragePlanError::InvalidBindings);
			return std::nullopt;
		}
		if (!targetPaths.insert(paths->basePath).second
			|| !targetPaths.insert(paths->tempPath).second
			|| !targetPaths.insert(paths->databasePath).second
			|| !targetPaths.insert(paths->authPath).second) {
			SetError(error, AccountStoragePlanError::PathCollision);
			return std::nullopt;
		}
		result._targets.push_back({
			.id = key.id,
			.dataName = dataName,
			.paths = std::move(*paths),
		});
	}
	std::ranges::sort(result._targets, {}, &AccountStorageTarget::id);
	SetError(error, AccountStoragePlanError::None);
	return std::optional<AccountStoragePlan>(std::move(result));
}

} // namespace Ayu::ProfileSets
