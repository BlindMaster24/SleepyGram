/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "storage/storage_account_paths.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <algorithm>
#include <cstring>

namespace Storage {

QString AccountDataName(const QString &dataName, int index) {
	auto result = dataName;
	result.replace('#', QString());
	if (index > 0) {
		result += '#' + QString::number(index + 1);
	}
	return result;
}
namespace {

QString ToFilePart(FileKey value) {
	auto result = QString();
	result.reserve(16);
	for (auto i = 0; i != 16; ++i) {
		const auto nibble = uchar(value & 0x0F);
		result.push_back((nibble < 0x0A)
			? QChar('0' + nibble)
			: QChar('A' + (nibble - 0x0A)));
		value >>= 4;
	}
	return result;
}

} // namespace

AccountPaths AccountPathsForDataName(
		const QString &globalPath,
		const QString &dataName) {
	auto base = globalPath;
	if (!base.endsWith('/')) {
		base += '/';
	}
	const auto nameBytes = dataName.toUtf8();
	const auto digest = QCryptographicHash::hash(
		nameBytes,
		QCryptographicHash::Md5);
	auto key = FileKey(0);
	static_assert(sizeof(key) == 8);
	std::memcpy(&key, digest.constData(), sizeof(key));
	const auto filePart = ToFilePart(key);
	return {
		.dataNameKey = key,
		.basePath = base + filePart + '/',
		.tempPath = base + "temp_" + dataName + '/',
		.databasePath = base + "user_" + dataName + '/',
		.authPath = base + filePart,
	};
}

std::optional<AccountPaths> ScopedAccountPaths(
		const QString &root,
		const QString &locator) {
	if (!QDir::isAbsolutePath(root)
		|| root.startsWith(':')
		|| root.contains(QChar(0))
		|| locator.size() != 32
		|| !std::ranges::all_of(locator, [](QChar ch) {
			return (ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
				|| (ch >= QLatin1Char('a') && ch <= QLatin1Char('f'));
		})) {
		return std::nullopt;
	}
	const auto base = QDir(QDir::cleanPath(root)).filePath(locator) + '/';
	return AccountPaths{
		.basePath = base + "data/",
		.tempPath = base + "temp/",
		.databasePath = base + "user/",
		.authPath = base + "auth",
		.mode = AccountStorageMode::Scoped,
	};
}

} // namespace Storage
