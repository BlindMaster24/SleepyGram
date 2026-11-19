/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QUrl>

#include <optional>

namespace Core::Updates {

struct GithubRelease {
	quint32 version = 0;
	QUrl download;
};

[[nodiscard]] std::optional<GithubRelease> ParseGithubRelease(
	const QByteArray &json,
	const QByteArray &platformKey,
	quint32 currentVersion);

} // namespace Core::Updates
