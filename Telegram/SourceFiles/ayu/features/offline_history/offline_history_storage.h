// This is the source code of AyuGram for Desktop.
#pragma once

#include "data/data_msg_id.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QStringList>

#include <vector>

namespace Ayu::OfflineHistory::Storage {

struct Message {
	MsgId id = 0;
	TimeId date = 0;
	QString sender;
	QString text;
};

struct Snapshot {
	int64 from = 0;
	int64 to = 0;
	int32 nextOffset = 0;
	int pages = 0;
	std::vector<Message> messages;
};

struct Paths {
	QString root;
	QString complete;
	QString partial;
};

[[nodiscard]] Paths PathsFor(
	const QString &root,
	uint64 accountId,
	PeerId peerId);
[[nodiscard]] QByteArray Serialize(
	const Snapshot &snapshot,
	uint64 accountId,
	PeerId peerId);
[[nodiscard]] bool ReadSnapshot(
	const QString &path,
	uint64 accountId,
	PeerId peerId,
	Snapshot *snapshot);
[[nodiscard]] qint64 UsageBytes(
	const QString &root,
	const QStringList &excluded = {});
[[nodiscard]] bool WriteAtomic(
	const QString &path,
	const QByteArray &bytes,
	const QString &root,
	int64 limit,
	const QStringList &excluded = {});

} // namespace Ayu::OfflineHistory::Storage
