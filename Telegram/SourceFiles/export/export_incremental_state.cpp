/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "export/export_incremental_state.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QSaveFile>

namespace Export {
namespace {

constexpr auto kCurrentStateVersion = 1;

[[nodiscard]] QString NormalizeFolderPrefix(const QString &folderPath) {
	if (folderPath.isEmpty()) {
		return QString();
	}
	const auto abs = QDir(folderPath).absolutePath();
	return abs.endsWith('/') ? abs : (abs + '/');
}

[[nodiscard]] uint64 ReadUint64(const QJsonObject &obj, const QString &key) {
	const auto val = obj.value(key);
	if (val.isString()) {
		return val.toString().toULongLong();
	}
	return static_cast<uint64>(val.toDouble(0));
}

[[nodiscard]] int64 ReadInt64(
		const QJsonObject &obj,
		const QString &key,
		int64 fallback = 0) {
	const auto val = obj.value(key);
	if (val.isUndefined() || val.isNull()) {
		return fallback;
	}
	if (val.isString()) {
		auto ok = false;
		const auto parsed = val.toString().toLongLong(&ok);
		return ok ? parsed : fallback;
	}
	return static_cast<int64>(val.toDouble(double(fallback)));
}

} // namespace

QString IncrementalStateFilePath(const QString &folderPath) {
	const auto prefix = NormalizeFolderPrefix(folderPath);
	return prefix.isEmpty()
		? QString()
		: (prefix + QString::fromLatin1(kIncrementalStateFilename));
}

std::optional<IncrementalState> LoadIncrementalState(
		const QString &folderPath) {
	const auto filePath = IncrementalStateFilePath(folderPath);
	if (filePath.isEmpty()) {
		return std::nullopt;
	}
	auto file = QFile(filePath);
	if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
		return std::nullopt;
	}
	auto error = QJsonParseError();
	const auto doc = QJsonDocument::fromJson(file.readAll(), &error);
	if (error.error != QJsonParseError::NoError || !doc.isObject()) {
		return std::nullopt;
	}
	const auto root = doc.object();
	if (root.value(u"version"_q).toInt() != kCurrentStateVersion) {
		return std::nullopt;
	}
	auto state = IncrementalState();
	state.version = kCurrentStateVersion;
	state.mode = root.value(u"mode"_q).toString();
	if (state.mode != u"single_peer"_q && state.mode != u"single_topic"_q) {
		return std::nullopt;
	}
	state.format = root.value(u"format"_q).toInt();
	state.accountUserId = ReadUint64(root, u"account_user_id"_q);
	state.peerId = ReadUint64(root, u"peer_id"_q);
	state.topicRootId = root.value(u"topic_root_id"_q).toInt();
	state.lastMessageId = root.value(u"last_message_id"_q).toInt();
	state.lastSplitIndex = root.value(u"last_split_index"_q).toInt();
	state.messagesCount = root.value(u"messages_count"_q).toInt();
	state.jsonCloseOffset = ReadInt64(root, u"json_close_offset"_q, -1);

	const auto counters = root.value(u"media_counters"_q).toObject();
	state.mediaCounters.photos = counters.value(u"photos"_q).toInt();
	state.mediaCounters.audios = counters.value(u"audios"_q).toInt();
	state.mediaCounters.videos = counters.value(u"videos"_q).toInt();
	state.mediaCounters.files = counters.value(u"files"_q).toInt();
	state.mediaCounters.contacts = counters.value(u"contacts"_q).toInt();

	const auto html = root.value(u"html"_q).toObject();
	if (!html.isEmpty()) {
		state.htmlLastFileIndex = html.value(u"last_file_index"_q).toInt();
		state.htmlLastFileCloseOffset = ReadInt64(
			html,
			u"last_file_close_offset"_q,
			-1);
		state.htmlDateMessageId = html.value(u"date_message_id"_q).toInt();
		for (const auto &v : html.value(u"last_message_ids_per_file"_q).toArray()) {
			state.htmlLastMessageIdsPerFile.push_back(v.toInt());
		}
		const auto lastMsg = html.value(u"last_message"_q).toObject();
		if (!lastMsg.isEmpty() && lastMsg.value(u"valid"_q).toBool()) {
			state.htmlLastMessage.valid = true;
			state.htmlLastMessage.id = lastMsg.value(u"id"_q).toInt();
			state.htmlLastMessage.isDefault
				= lastMsg.value(u"is_default"_q).toBool();
			state.htmlLastMessage.fromId = ReadUint64(lastMsg, u"from_id"_q);
			state.htmlLastMessage.viaBotId = ReadUint64(lastMsg, u"via_bot_id"_q);
			state.htmlLastMessage.date = ReadInt64(lastMsg, u"date"_q);
			state.htmlLastMessage.forwardedFromId = ReadUint64(
				lastMsg,
				u"forwarded_from_id"_q);
			state.htmlLastMessage.forwardedFromName
				= lastMsg.value(u"forwarded_from_name"_q).toString();
			state.htmlLastMessage.forwarded
				= lastMsg.value(u"forwarded"_q).toBool();
			state.htmlLastMessage.showForwardedAsOriginal
				= lastMsg.value(u"show_forwarded_as_original"_q).toBool();
			state.htmlLastMessage.forwardedDate = ReadInt64(
				lastMsg,
				u"forwarded_date"_q);
		}
	}

	const auto files = root.value(u"files"_q).toArray();
	state.files.reserve(files.size());
	for (const auto &v : files) {
		const auto obj = v.toObject();
		auto entry = IncrementalFileEntry{
			.type = ReadUint64(obj, u"t"_q),
			.id = ReadUint64(obj, u"i"_q),
			.relativePath = obj.value(u"p"_q).toString(),
			.size = ReadInt64(obj, u"s"_q),
		};
		if (!entry.relativePath.isEmpty()) {
			state.files.push_back(std::move(entry));
		}
	}
	return state;
}

bool SaveIncrementalState(
		const QString &folderPath,
		const IncrementalState &state) {
	const auto filePath = IncrementalStateFilePath(folderPath);
	if (filePath.isEmpty()) {
		return false;
	}
	auto root = QJsonObject();
	root.insert(u"version"_q, kCurrentStateVersion);
	root.insert(u"mode"_q, state.mode);
	root.insert(u"format"_q, state.format);
	root.insert(u"account_user_id"_q, QString::number(state.accountUserId));
	root.insert(u"peer_id"_q, QString::number(state.peerId));
	root.insert(u"topic_root_id"_q, state.topicRootId);
	root.insert(u"last_message_id"_q, state.lastMessageId);
	root.insert(u"last_split_index"_q, state.lastSplitIndex);
	root.insert(u"messages_count"_q, state.messagesCount);
	root.insert(
		u"json_close_offset"_q,
		QString::number(state.jsonCloseOffset));

	auto counters = QJsonObject();
	counters.insert(u"photos"_q, state.mediaCounters.photos);
	counters.insert(u"audios"_q, state.mediaCounters.audios);
	counters.insert(u"videos"_q, state.mediaCounters.videos);
	counters.insert(u"files"_q, state.mediaCounters.files);
	counters.insert(u"contacts"_q, state.mediaCounters.contacts);
	root.insert(u"media_counters"_q, counters);

	auto html = QJsonObject();
	html.insert(u"last_file_index"_q, state.htmlLastFileIndex);
	html.insert(
		u"last_file_close_offset"_q,
		QString::number(state.htmlLastFileCloseOffset));
	html.insert(u"date_message_id"_q, state.htmlDateMessageId);
	auto perFile = QJsonArray();
	for (const auto id : state.htmlLastMessageIdsPerFile) {
		perFile.append(id);
	}
	html.insert(u"last_message_ids_per_file"_q, perFile);
	if (state.htmlLastMessage.valid) {
		auto lastMsg = QJsonObject();
		lastMsg.insert(u"valid"_q, true);
		lastMsg.insert(u"id"_q, state.htmlLastMessage.id);
		lastMsg.insert(u"is_default"_q, state.htmlLastMessage.isDefault);
		lastMsg.insert(
			u"from_id"_q,
			QString::number(state.htmlLastMessage.fromId));
		lastMsg.insert(
			u"via_bot_id"_q,
			QString::number(state.htmlLastMessage.viaBotId));
		lastMsg.insert(
			u"date"_q,
			QString::number(state.htmlLastMessage.date));
		lastMsg.insert(
			u"forwarded_from_id"_q,
			QString::number(state.htmlLastMessage.forwardedFromId));
		lastMsg.insert(
			u"forwarded_from_name"_q,
			state.htmlLastMessage.forwardedFromName);
		lastMsg.insert(u"forwarded"_q, state.htmlLastMessage.forwarded);
		lastMsg.insert(
			u"show_forwarded_as_original"_q,
			state.htmlLastMessage.showForwardedAsOriginal);
		lastMsg.insert(
			u"forwarded_date"_q,
			QString::number(state.htmlLastMessage.forwardedDate));
		html.insert(u"last_message"_q, lastMsg);
	}
	root.insert(u"html"_q, html);

	auto files = QJsonArray();
	for (const auto &entry : state.files) {
		auto obj = QJsonObject();
		obj.insert(u"t"_q, QString::number(entry.type));
		obj.insert(u"i"_q, QString::number(entry.id));
		obj.insert(u"p"_q, entry.relativePath);
		obj.insert(u"s"_q, QString::number(entry.size));
		files.append(obj);
	}
	root.insert(u"files"_q, files);

	auto save = QSaveFile(filePath);
	if (!save.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		return false;
	}
	const auto bytes = QJsonDocument(root).toJson(QJsonDocument::Compact);
	if (save.write(bytes) != bytes.size()) {
		save.cancelWriting();
		return false;
	}
	return save.commit();
}

bool MatchesIncrementalTarget(
		const IncrementalState &state,
		uint64 accountUserId,
		uint64 peerId,
		int32 topicRootId) {
	if (state.version != kCurrentStateVersion
		|| state.lastMessageId <= 0
		|| state.peerId == 0
		|| state.peerId != peerId) {
		return false;
	}
	if (accountUserId != 0
		&& state.accountUserId != 0
		&& state.accountUserId != accountUserId) {
		return false;
	}
	if (topicRootId != 0) {
		return (state.mode == u"single_topic"_q)
			&& (state.topicRootId == topicRootId);
	}
	return (state.mode == u"single_peer"_q) && (state.topicRootId == 0);
}

} // namespace Export
