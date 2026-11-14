// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/data/ayu_database.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace AyuArchiveBackup {

struct Preview {
	AyuDatabase::ArchiveBackupSnapshot snapshot;
	QString summary;
};

[[nodiscard]] QByteArray Create(ID accountId, const QString &password);
[[nodiscard]] std::optional<Preview> Read(
	QByteArray bytes,
	ID expectedAccountId,
	const QString &password);
[[nodiscard]] AyuDatabase::ArchiveImportCounts Import(
	ID accountId,
	const Preview &preview);

} // namespace AyuArchiveBackup
