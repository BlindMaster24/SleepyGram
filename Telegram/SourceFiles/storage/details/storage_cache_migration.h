// This is the source code of AyuGram for Desktop.
#pragma once

#include "storage/storage_account_paths.h"

#include <QtCore/QStringList>

namespace Storage {

class EncryptionKey;

namespace details {

enum class CacheMigrationResult : uchar {
	Success,
	InvalidPaths,
	InvalidKeys,
	UnsupportedSource,
	InvalidSource,
	DestinationIo,
	VerificationFailed,
};

struct CacheMigrationInventory final {
	QStringList directories;
	QStringList files;
};

// The caller quiesces both trees and publishes the enclosing staged account.
[[nodiscard]] CacheMigrationResult CompareAccountCachesForMigration(
	const QString &legacyDatabasePath,
	const QString &scopedDatabasePath,
	const EncryptionKey &legacyKey,
	const EncryptionKey &scopedKey,
	bool write,
	CacheMigrationInventory *inventory = nullptr,
	LegacyWebviewTransfer webview = LegacyWebviewTransfer::RequireIsolated);

} // namespace details
} // namespace Storage
