// This is the source code of AyuGram for Desktop.
#pragma once

#include "storage/storage_account_paths.h"

#include <QtCore/QByteArray>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QOperatingSystemVersion>

namespace Webview {
struct StorageId;
} // namespace Webview

namespace Ayu::ProfileSets {

[[nodiscard]] bool CanUsePersistentWebview(const Webview::StorageId &id);

namespace details {

[[nodiscard]] inline bool CanUsePersistentWebview(
		bool legacy,
		QOperatingSystemVersion::OSType platform,
		int majorVersion,
		const QString &accountsRoot,
		const QString &path,
		const QByteArray &token) {
	if (legacy) {
		return true;
	}
	using OS = QOperatingSystemVersion;
	if ((platform != OS::Unknown && platform != OS::MacOS)
		|| token.size() != 16
		|| (platform == OS::MacOS
			&& (majorVersion < 14 || token == QByteArray(16, '\0')))) {
		return false;
	}
	const auto root = QDir(accountsRoot);
	const auto locator = root.relativeFilePath(path).section('/', 0, 0);
	const auto account = Storage::ScopedAccountPaths(accountsRoot, locator);
	if (!account || (path != account->databasePath + QLatin1String("wvbots")
		&& path != account->databasePath + QLatin1String("wvother"))) {
		return false;
	}
	const auto folder = root.filePath(locator);
	if (QDir(folder).canonicalPath() != folder) {
		return false;
	}
	const auto safeDirectory = [](const QString &name) {
		const auto info = QFileInfo(name);
		return !info.isSymLink()
			&& !info.isJunction()
			&& (!info.exists() || (info.isDir() && info.canonicalFilePath() == name));
	};
	return safeDirectory(QDir::cleanPath(account->databasePath))
		&& safeDirectory(path);
}

} // namespace details
} // namespace Ayu::ProfileSets
