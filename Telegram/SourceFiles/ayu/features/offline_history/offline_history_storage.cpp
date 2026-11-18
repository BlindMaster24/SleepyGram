// This is the source code of AyuGram for Desktop.
#include "ayu/features/offline_history/offline_history_storage.h"

#include <QtCore/QDir>
#include <QtCore/QDirIterator>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QSaveFile>

#include <algorithm>
#include <utility>

namespace Ayu::OfflineHistory::Storage {
namespace {

constexpr auto kFormatVersion = 1;
constexpr auto kMaxMessages = 10000;
constexpr auto kMaxSnapshotBytes = 64LL * 1024 * 1024;
constexpr auto kMaxTextBytes = 48LL * 1024 * 1024;
constexpr auto kMaxMessageTextLength = 16 * 1024;
constexpr auto kMaxRangeSeconds = 7LL * 24 * 60 * 60;
constexpr auto kMaxAttachments = 10000;
constexpr auto kMaxAttachmentBytes = 25LL * 1024 * 1024;
constexpr auto kMaxManifestBytes = 8LL * 1024 * 1024;

bool SafeFileName(const Attachment &attachment) {
	if (!attachment.messageId
		|| attachment.messageId.bare > 0x3FFFFFFF
		|| attachment.mediaId <= 0
		|| attachment.fileName.isEmpty()
		|| QFileInfo(attachment.fileName).fileName() != attachment.fileName) {
		return false;
	}
	const auto prefix = QStringLiteral("m-%1-%2-%3.")
		.arg(attachment.messageId.bare)
		.arg(attachment.photo ? QStringLiteral("p") : QStringLiteral("d"))
		.arg(attachment.mediaId);
	if (!attachment.fileName.startsWith(prefix)) {
		return false;
	}
	const auto suffix = attachment.fileName.mid(prefix.size());
	if (suffix.isEmpty() || suffix.size() > 10) {
		return false;
	}
	return std::ranges::all_of(suffix, [](QChar ch) {
		return (ch >= QLatin1Char('a') && ch <= QLatin1Char('z'))
			|| (ch >= QLatin1Char('0') && ch <= QLatin1Char('9'));
	});
}

bool ValidAttachments(const std::vector<Attachment> &attachments) {
	if (attachments.size() > kMaxAttachments) {
		return false;
	}
	auto names = QStringList();
	for (const auto &attachment : attachments) {
		if (!SafeFileName(attachment)
			|| attachment.name.size() > 1024
			|| attachment.size <= 0
			|| attachment.size > kMaxAttachmentBytes
			|| attachment.sourceSize <= 0
			|| attachment.sourceSize > kMaxAttachmentBytes
			|| names.contains(attachment.fileName)) {
			return false;
		}
		names.push_back(attachment.fileName);
	}
	return true;
}

bool Valid(const Snapshot &snapshot) {
	if (snapshot.from <= 0
		|| snapshot.to < snapshot.from
		|| snapshot.to - snapshot.from > kMaxRangeSeconds
		|| snapshot.pages < 0
		|| snapshot.pages > 100
		|| snapshot.nextOffset < 0
		|| snapshot.nextOffset > 0x3FFFFFFF
		|| snapshot.messages.size() > kMaxMessages) {
		return false;
	}
	auto textBytes = int64(0);
	for (const auto &message : snapshot.messages) {
		if (!message.id
			|| message.id.bare > 0x3FFFFFFF
			|| message.date < snapshot.from
			|| message.date > snapshot.to
			|| message.text.size() > kMaxMessageTextLength) {
			return false;
		}
		textBytes += message.text.toUtf8().size();
		if (textBytes > kMaxTextBytes) {
			return false;
		}
	}
	return true;
}

QJsonObject Encode(const Snapshot &snapshot, uint64 accountId, PeerId peerId) {
	auto object = QJsonObject();
	object.insert(QStringLiteral("version"), kFormatVersion);
	object.insert(QStringLiteral("account"), QString::number(accountId));
	object.insert(QStringLiteral("peer"), QString::number(peerId.value));
	object.insert(QStringLiteral("from"), snapshot.from);
	object.insert(QStringLiteral("to"), snapshot.to);
	object.insert(QStringLiteral("nextOffset"), snapshot.nextOffset);
	object.insert(QStringLiteral("pages"), snapshot.pages);
	const auto messages = [&] {
		auto result = QJsonArray();
		for (const auto &message : snapshot.messages) {
			auto item = QJsonObject();
			item.insert(QStringLiteral("id"), QString::number(message.id.bare));
			item.insert(QStringLiteral("date"), message.date);
			item.insert(QStringLiteral("sender"), message.sender);
			item.insert(QStringLiteral("text"), message.text);
			result.push_back(item);
		}
		return result;
	}();
	object.insert(QStringLiteral("messages"), messages);
	return object;
}

QJsonObject EncodeAttachments(
		const std::vector<Attachment> &attachments,
		uint64 accountId,
		PeerId peerId) {
	auto object = QJsonObject();
	object.insert(QStringLiteral("version"), kFormatVersion);
	object.insert(QStringLiteral("account"), QString::number(accountId));
	object.insert(QStringLiteral("peer"), QString::number(peerId.value));
	auto array = QJsonArray();
	for (const auto &attachment : attachments) {
		auto item = QJsonObject();
		item.insert(QStringLiteral("message"), QString::number(attachment.messageId.bare));
		item.insert(QStringLiteral("media"), QString::number(attachment.mediaId));
		item.insert(QStringLiteral("photo"), attachment.photo);
		item.insert(QStringLiteral("name"), attachment.name);
		item.insert(QStringLiteral("file"), attachment.fileName);
		item.insert(QStringLiteral("size"), attachment.size);
		item.insert(QStringLiteral("sourceSize"), attachment.sourceSize);
		array.push_back(item);
	}
	object.insert(QStringLiteral("attachments"), array);
	return object;
}

} // namespace

Paths PathsFor(const QString &root, uint64 accountId, PeerId peerId) {
	const auto directory = root
		+ '/'
		+ QString::number(accountId)
		+ '/'
		+ QString::number(peerId.value);
	return {
		.root = root,
		.complete = directory + QStringLiteral("/history.json"),
		.partial = directory + QStringLiteral("/history.partial.json"),
		.attachmentDirectory = directory + QStringLiteral("/attachments"),
		.attachmentManifest = directory + QStringLiteral("/attachments.json"),
	};
}

QByteArray Serialize(
		const Snapshot &snapshot,
		uint64 accountId,
		PeerId peerId) {
	if (!Valid(snapshot)) {
		return {};
	}
	return QJsonDocument(Encode(snapshot, accountId, peerId))
		.toJson(QJsonDocument::Compact);
}

bool ReadSnapshot(
		const QString &path,
		uint64 accountId,
		PeerId peerId,
		Snapshot *snapshot) {
	const auto info = QFileInfo(path);
	if (!snapshot
		|| !info.exists()
		|| !info.isFile()
		|| info.size() > kMaxSnapshotBytes) {
		return false;
	}
	auto file = QFile(path);
	if (!file.open(QIODevice::ReadOnly)) {
		return false;
	}
	const auto bytes = file.read(kMaxSnapshotBytes + 1);
	return file.atEnd() && DecodeSnapshot(bytes, accountId, peerId, snapshot);
}

bool DecodeSnapshot(
		const QByteArray &bytes,
		uint64 accountId,
		PeerId peerId,
		Snapshot *snapshot) {
	if (!snapshot || bytes.size() > kMaxSnapshotBytes) {
		return false;
	}
	const auto document = QJsonDocument::fromJson(bytes);
	if (!document.isObject()) {
		return false;
	}
	const auto object = document.object();
	if (object.value(QStringLiteral("version")).toInt() != kFormatVersion
		|| object.value(QStringLiteral("account")).toString()
			!= QString::number(accountId)
		|| object.value(QStringLiteral("peer")).toString()
			!= QString::number(peerId.value)) {
		return false;
	}
	snapshot->from = object.value(QStringLiteral("from")).toInteger();
	snapshot->to = object.value(QStringLiteral("to")).toInteger();
	snapshot->nextOffset = object.value(QStringLiteral("nextOffset")).toInt();
	snapshot->pages = object.value(QStringLiteral("pages")).toInt();
	const auto messages = object.value(QStringLiteral("messages")).toArray();
	if (snapshot->from <= 0
		|| snapshot->to < snapshot->from
		|| (snapshot->to - snapshot->from) > kMaxRangeSeconds
		|| snapshot->pages < 0
		|| snapshot->pages > 100
		|| snapshot->nextOffset < 0
		|| snapshot->nextOffset > 0x3FFFFFFF
		|| messages.size() > kMaxMessages) {
		return false;
	}
	snapshot->messages.clear();
	snapshot->messages.reserve(messages.size());
	for (const auto &value : messages) {
		const auto item = value.toObject();
		const auto id = item.value(QStringLiteral("id")).toString().toLongLong();
		const auto date = item.value(QStringLiteral("date")).toInteger();
		const auto text = item.value(QStringLiteral("text")).toString();
		if (id <= 0
			|| id > 0x3FFFFFFF
			|| date < snapshot->from
			|| date > snapshot->to
			|| text.size() > kMaxMessageTextLength) {
			return false;
		}
		snapshot->messages.push_back({
			.id = MsgId(id),
			.date = TimeId(date),
			.sender = item.value(QStringLiteral("sender")).toString(),
			.text = text,
		});
	}
	return Valid(*snapshot);
}

qint64 UsageBytes(const QString &root, const QStringList &excluded) {
	auto result = qint64(0);
	if (!QDir(root).exists()) {
		return result;
	}
	for (auto i = QDirIterator(
			root,
			QDir::Files,
			QDirIterator::Subdirectories);
		i.hasNext();) {
		const auto path = QFileInfo(i.next()).absoluteFilePath();
		if (!excluded.contains(path)) {
			result += QFileInfo(path).size();
		}
	}
	return result;
}

bool WriteAtomic(
		const QString &path,
		const QByteArray &bytes,
		const QString &root,
		int64 limit,
		const QStringList &excluded) {
	if (bytes.size() > kMaxSnapshotBytes) {
		return false;
	}
	const auto normalized = QFileInfo(path).absoluteFilePath();
	auto skip = excluded;
	if (!skip.contains(normalized)) {
		skip.push_back(normalized);
	}
	if (UsageBytes(root, skip) + bytes.size() > limit) {
		return false;
	}
	if (!QDir().mkpath(QFileInfo(path).absolutePath())) {
		return false;
	}
	auto file = QSaveFile(path);
	return file.open(QIODevice::WriteOnly)
		&& (file.write(bytes) == bytes.size())
		&& file.commit();
}

QByteArray SerializeAttachments(
		const std::vector<Attachment> &attachments,
		uint64 accountId,
		PeerId peerId) {
	if (!ValidAttachments(attachments)) {
		return {};
	}
	return QJsonDocument(EncodeAttachments(attachments, accountId, peerId))
		.toJson(QJsonDocument::Compact);
}

bool ReadAttachments(
		const Paths &paths,
		uint64 accountId,
		PeerId peerId,
		std::vector<Attachment> *attachments) {
	if (!attachments) {
		return false;
	}
	attachments->clear();
	const auto directoryInfo = QFileInfo(paths.attachmentDirectory);
	if (directoryInfo.exists()
		&& (!directoryInfo.isDir() || directoryInfo.isSymLink())) {
		attachments->clear();
		return false;
	}
	auto file = QFile(paths.attachmentManifest);
	if (!file.exists()) {
		attachments->clear();
		return true;
	}
	const auto info = QFileInfo(file);
	if (!info.isFile() || info.isSymLink()
		|| info.size() > kMaxManifestBytes
		|| !file.open(QIODevice::ReadOnly)) {
		return false;
	}
	const auto bytes = file.read(kMaxManifestBytes + 1);
	auto result = std::vector<Attachment>();
	if (!file.atEnd() || !DecodeAttachments(bytes, accountId, peerId, &result)) {
		return false;
	}
	std::erase_if(result, [&](const auto &attachment) {
		const auto fileInfo = QFileInfo(QDir(paths.attachmentDirectory).filePath(attachment.fileName));
		return !fileInfo.isFile() || fileInfo.isSymLink() || fileInfo.size() != attachment.size;
	});
	*attachments = std::move(result);
	return true;
}

bool DecodeAttachments(
		const QByteArray &bytes,
		uint64 accountId,
		PeerId peerId,
		std::vector<Attachment> *attachments) {
	if (!attachments || bytes.size() > kMaxManifestBytes) {
		return false;
	}
	const auto document = QJsonDocument::fromJson(bytes);
	if (!document.isObject()) {
		return false;
	}
	const auto object = document.object();
	if (object.value(QStringLiteral("version")).toInt() != kFormatVersion
		|| object.value(QStringLiteral("account")).toString()
			!= QString::number(accountId)
		|| object.value(QStringLiteral("peer")).toString()
			!= QString::number(peerId.value)) {
		return false;
	}
	const auto array = object.value(QStringLiteral("attachments")).toArray();
	if (array.size() > kMaxAttachments) {
		return false;
	}
	auto result = std::vector<Attachment>();
	result.reserve(array.size());
	for (const auto &value : array) {
		const auto item = value.toObject();
		auto attachment = Attachment{
			.messageId = MsgId(item.value(QStringLiteral("message"))
				.toString().toLongLong()),
			.mediaId = item.value(QStringLiteral("media"))
				.toString().toULongLong(),
			.photo = item.value(QStringLiteral("photo")).toBool(),
			.name = item.value(QStringLiteral("name")).toString(),
			.fileName = item.value(QStringLiteral("file")).toString(),
			.size = item.value(QStringLiteral("size")).toInteger(),
			.sourceSize = item.value(QStringLiteral("sourceSize")).toInteger(),
		};
		if (!ValidAttachments({ attachment })) {
			return false;
		}
		result.push_back(std::move(attachment));
	}
	if (!ValidAttachments(result)) {
		return false;
	}
	*attachments = std::move(result);
	return true;
}

} // namespace Ayu::OfflineHistory::Storage
