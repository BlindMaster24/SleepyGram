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

namespace Ayu::OfflineHistory::Storage {
namespace {

constexpr auto kFormatVersion = 1;
constexpr auto kMaxMessages = 10000;
constexpr auto kMaxSnapshotBytes = 64LL * 1024 * 1024;
constexpr auto kMaxTextBytes = 48LL * 1024 * 1024;
constexpr auto kMaxMessageTextLength = 16 * 1024;
constexpr auto kMaxRangeSeconds = 7LL * 24 * 60 * 60;

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
	object.insert(u"messages"_q, messages);
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
	if (bytes.size() > kMaxSnapshotBytes || !file.atEnd()) {
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

} // namespace Ayu::OfflineHistory::Storage
