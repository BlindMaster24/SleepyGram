/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

#include <QtCore/QString>
#include <optional>
#include <vector>

namespace Export {

inline constexpr auto kIncrementalStateFilename
	= "sleepygram_export_state.json";

struct IncrementalFileEntry {
	uint64 type = 0;
	uint64 id = 0;
	QString relativePath;
	int64 size = 0;
};

struct IncrementalMediaCounters {
	int photos = 0;
	int audios = 0;
	int videos = 0;
	int files = 0;
	int contacts = 0;
};

struct IncrementalHtmlLastMessage {
	bool valid = false;
	int id = 0;
	bool isDefault = false;
	uint64 fromId = 0;
	uint64 viaBotId = 0;
	int64 date = 0;
	uint64 forwardedFromId = 0;
	QString forwardedFromName;
	bool forwarded = false;
	bool showForwardedAsOriginal = false;
	int64 forwardedDate = 0;
};

struct IncrementalState {
	int version = 1;
	QString mode;
	int format = 0;
	uint64 accountUserId = 0;
	uint64 peerId = 0;
	int32 topicRootId = 0;
	int32 lastMessageId = 0;
	int lastSplitIndex = 0;
	int messagesCount = 0;
	IncrementalMediaCounters mediaCounters;
	int64 jsonCloseOffset = -1;
	int htmlLastFileIndex = 0;
	int64 htmlLastFileCloseOffset = -1;
	int htmlDateMessageId = 0;
	std::vector<int> htmlLastMessageIdsPerFile;
	IncrementalHtmlLastMessage htmlLastMessage;
	std::vector<IncrementalFileEntry> files;
};

[[nodiscard]] QString IncrementalStateFilePath(const QString &folderPath);
[[nodiscard]] std::optional<IncrementalState> LoadIncrementalState(
	const QString &folderPath);
bool SaveIncrementalState(
	const QString &folderPath,
	const IncrementalState &state);
[[nodiscard]] bool MatchesIncrementalTarget(
	const IncrementalState &state,
	uint64 accountUserId,
	uint64 peerId,
	int32 topicRootId);

} // namespace Export
