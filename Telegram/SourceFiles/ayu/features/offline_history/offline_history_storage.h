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

struct Attachment {
	MsgId messageId = 0;
	uint64 mediaId = 0;
	bool photo = false;
	QString name;
	QString fileName;
	qint64 size = 0;
	qint64 sourceSize = 0;
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
	QString attachmentDirectory;
	QString attachmentManifest;
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
[[nodiscard]] bool DecodeSnapshot(
	const QByteArray &bytes,
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
[[nodiscard]] bool ReadAttachments(
	const Paths &paths,
	uint64 accountId,
	PeerId peerId,
	std::vector<Attachment> *attachments);
[[nodiscard]] bool DecodeAttachments(
	const QByteArray &bytes,
	uint64 accountId,
	PeerId peerId,
	std::vector<Attachment> *attachments);
[[nodiscard]] QByteArray SerializeAttachments(
	const std::vector<Attachment> &attachments,
	uint64 accountId,
	PeerId peerId);

} // namespace Ayu::OfflineHistory::Storage
