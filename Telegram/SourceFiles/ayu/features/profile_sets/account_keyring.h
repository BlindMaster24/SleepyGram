/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ayu/features/profile_sets/profile_sets.h"
#include "base/bytes.h"

#include <optional>
#include <vector>

namespace Ayu::ProfileSets {

inline constexpr auto kAccountKeySize = 32;
inline constexpr auto kAccountLocalStorageKeySize = 256;
inline constexpr auto kAccountKeyringWrappingKeySize = 32;
inline constexpr auto kAccountKeyringVersion = quint32(1);

struct AccountKey final {
	AccountId id;
	QByteArray key;

	friend inline bool operator==(const AccountKey&, const AccountKey&) = default;
};

enum class KeyringError : uchar {
	None,
	InvalidWrappingKey,
	InvalidAccountId,
	InvalidAccountKey,
	DuplicateAccountId,
	DuplicateAccountKey,
	TooManyAccounts,
	RandomFailure,
	Malformed,
	UnsupportedVersion,
	AuthenticationFailed,
};

[[nodiscard]] std::optional<AccountKey> NewAccountKey(
	AccountId id,
	KeyringError *error = nullptr);
[[nodiscard]] bool DeriveAccountLocalStorageKey(
	const AccountKey &account,
	bytes::span output);
[[nodiscard]] KeyringError ValidateAccountKeys(
	const std::vector<AccountKey> &accounts);
[[nodiscard]] QByteArray SealAccountKeyring(
	const std::vector<AccountKey> &accounts,
	const QByteArray &wrappingKey,
	KeyringError *error = nullptr);
[[nodiscard]] std::optional<std::vector<AccountKey>> OpenAccountKeyring(
	const QByteArray &sealed,
	const QByteArray &wrappingKey,
	KeyringError *error = nullptr);

} // namespace Ayu::ProfileSets
