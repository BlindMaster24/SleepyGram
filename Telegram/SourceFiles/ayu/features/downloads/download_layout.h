/*
This file is part of SleepyGram Desktop,
an unofficial client based on AyuGram Desktop and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>

class DocumentData;
class HistoryItem;
class PhotoData;

namespace Main {
class Session;
} // namespace Main

namespace Ayu::Downloads {

[[nodiscard]] bool OrganizeByTopic();
[[nodiscard]] bool OrganizeByType();
[[nodiscard]] bool IsOrganizationEnabled();

[[nodiscard]] QString SanitizePathSegment(const QString &raw);

[[nodiscard]] QString ResolveDirectory(
	const QString &basePath,
	not_null<Main::Session*> session,
	const HistoryItem *item,
	DocumentData *document,
	PhotoData *photo);

} // namespace Ayu::Downloads
