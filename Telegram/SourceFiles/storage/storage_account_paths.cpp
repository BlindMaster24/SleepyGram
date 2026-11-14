/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "storage/storage_account_paths.h"

#include <QtCore/QCryptographicHash>
#include <cstring>

namespace Storage {
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
	};
}

} // namespace Storage
