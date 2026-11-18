/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>
#include <QtCore/QtGlobal>
#include <optional>

namespace Storage {

using FileKey = quint64;

enum class AccountStorageMode : uchar {
	Legacy,
	Scoped,
};

struct AccountPaths final {
	FileKey dataNameKey = 0;
	QString basePath;
	QString tempPath;
	QString databasePath;
	QString authPath;
	AccountStorageMode mode = AccountStorageMode::Legacy;
};

[[nodiscard]] AccountPaths AccountPathsForDataName(
	const QString &globalPath,
	const QString &dataName);

[[nodiscard]] std::optional<AccountPaths> ScopedAccountPaths(
	const QString &root,
	const QString &locator);

} // namespace Storage
