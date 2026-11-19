/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>

#include <filesystem>

namespace Storage {

[[nodiscard]] inline std::filesystem::path NativeFilePath(const QString &path) {
#ifdef Q_OS_WIN
	return std::filesystem::path(path.toStdWString());
#else // Q_OS_WIN
	return std::filesystem::path(path.toStdString());
#endif // Q_OS_WIN
}

} // namespace Storage
